from werkzeug.security import generate_password_hash
from app.db.database import AsyncSessionLocal
import app.db.crud as crud
import app.core.encryption as encryption
import app.core.cache as cache
from app.core.tasks import update_progress, complete_task, fail_task


async def migrate_passwords(user_id: str, old_password: str, new_password: str, task_id: str):
    try:
        async with AsyncSessionLocal() as db:
            user = await crud.get_user_by_email(db, user_id)
            if not user:
                fail_task(task_id, "User not found")
                return

            entries = await crud.get_password_entries_by_owner(db, user_id)
            total = len(entries)

            if total == 0:
                new_public_key, new_private_key_enc = encryption.encode_key(new_password)
                new_password_hash = generate_password_hash(new_password)
                await crud.update_user(db, user_id, {
                    "public_key": new_public_key,
                    "private_key": new_private_key_enc,
                    "password": new_password_hash,
                })
                complete_task(task_id)
                return

            update_progress(task_id, 0, total)

            old_private_key = encryption.decode_key(user.private_key, old_password)

            new_public_key, new_private_key_enc = encryption.encode_key(new_password)

            skipped = 0
            for i, entry in enumerate(entries):
                try:
                    decrypted_password = encryption.decode_data(entry.password, old_private_key)
                    new_encrypted_password = encryption.encode_data(decrypted_password, new_public_key)
                    await crud.update_password_entry(db, entry.id, {"password": new_encrypted_password})
                except Exception:
                    skipped += 1

                update_progress(task_id, i + 1, total)

            new_password_hash = generate_password_hash(new_password)
            await crud.update_user(db, user_id, {
                "public_key": new_public_key,
                "private_key": new_private_key_enc,
                "password": new_password_hash,
            })

            await cache.cache_delete(f"user_entries:{user_id}")

            if skipped == total:
                fail_task(task_id, "Failed to migrate all password entries")
            else:
                complete_task(task_id)

    except Exception as e:
        fail_task(task_id, str(e))
