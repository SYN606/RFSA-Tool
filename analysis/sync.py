import requests
import gzip
import json
import os
from tqdm import tqdm
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
from analysis.models import init_db, FirmwareSignature, SessionLocal, Metadata
from config.settings import TARGET_VENDORS, FEED_FILE_PATH, NVD_FEED_URL


def download_feed(url, filename=FEED_FILE_PATH):
    print("⬇️ Downloading NVD feed...")
    try:
        r = requests.get(url, stream=True, timeout=30)
        r.raise_for_status()
    except Exception as e:
        print(f"❌ Failed to download feed: {e}")
        raise
    with open(filename, "wb") as f:
        for chunk in tqdm(r.iter_content(8192), desc="Downloading"):
            f.write(chunk)
    return filename


def extract_feed(filepath):
    print("📦 Extracting feed...")
    try:
        with gzip.open(filepath, 'rt', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Failed to extract feed: {e}")
        raise


def parse_and_store(data):
    session = SessionLocal()
    added = 0

    for item in data.get("CVE_Items", []):
        cve_id = item['cve']['CVE_data_meta']['ID']
        description_data = item['cve']['description']['description_data']
        description = description_data[0][
            'value'] if description_data else "No description."

        # Check if 'affects' exists in the item and handle missing key
        affects = item['cve'].get('affects')
        if affects and 'vendor' in affects:
            for vendor_data in affects['vendor'].get('vendor_data', []):
                vendor_name = vendor_data['vendor_name'].lower()
                if vendor_name not in TARGET_VENDORS:
                    continue

                for prod in vendor_data['product']['product_data']:
                    model = prod['product_name']
                    for ver in prod['version']['version_data']:
                        version = ver['version_value']

                        firmware_entry = FirmwareSignature(
                            vendor=vendor_name,
                            model=model,
                            version=version,
                            cve_id=cve_id,
                            description=description)

                        try:
                            session.add(firmware_entry)
                            session.commit()
                            added += 1
                        except IntegrityError:
                            session.rollback()
                        except Exception as e:
                            print(f"❌ DB error: {e}")
                            session.rollback()

    session.close()
    print(f"✅ Added {added} new CVE entries.")


def is_update_needed():
    session = SessionLocal()
    metadata = session.query(Metadata).filter(
        Metadata.key == 'last_update').first()

    if not metadata:
        session.close()
        return True

    last_update = metadata.value  # type: ignore

    try:
        # Handle potential fractional seconds in the timestamp
        last_update_time = datetime.strptime(last_update, # type: ignore
                                             "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        try:
            # Fallback for dates without fractional seconds
            last_update_time = datetime.strptime(last_update, # type: ignore
                                                 "%Y-%m-%d %H:%M:%S")
        except ValueError as e:
            print(f"Error parsing date: {e}")
            session.close()
            return True

    session.close()

    # Check if the last update is older than 7 days
    return datetime.now() - last_update_time > timedelta(days=7)


# === Update the metadata with the last update timestamp ===
def update_last_sync():
    session = SessionLocal()

    metadata = session.query(Metadata).filter(
        Metadata.key == 'last_update').first()
    if not metadata:
        # Create new entry if it doesn't exist
        metadata = Metadata(key='last_update', value=str(datetime.now()))
        session.add(metadata)
    else:
        metadata.value = str(datetime.now())  # type: ignore

    try:
        session.commit()
    except IntegrityError:
        session.rollback()
    except Exception as e:
        print(f"❌ Failed to update metadata: {e}")
        session.rollback()
    session.close()


def sync_nvd_feed():
    try:
        init_db()
        if not is_update_needed():
            print("⏳ Last update was within 7 days, skipping sync.")
            return

        print("🔄 Syncing the NVD Feed...")

        zip_path = download_feed(NVD_FEED_URL)
        data = extract_feed(zip_path)
        parse_and_store(data)

        update_last_sync()

        os.remove(zip_path)
        print("🧹 Removed temporary files.")

        print(f"🧠 Sync complete at {datetime.now()}")
    except Exception as e:
        print(f"❌ NVD sync failed: {e}")


if __name__ == "__main__":
    sync_nvd_feed()
