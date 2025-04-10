import os
import subprocess
import logging

logger = logging.getLogger(__name__)

def extract_firmware(firmware_file, verbose=False, overwrite=True, cleanup=False):
    extracted_dir = "extracted_firmware.bin"
    
    if os.path.exists(extracted_dir) and overwrite:
        subprocess.run(['rm', '-rf', extracted_dir], check=False)
    
    # Try binwalk (version 2.1.0 compatible)
    try:
        logger.info(f"Attempting extraction with binwalk for {firmware_file}")
        cmd = ['binwalk', '-e', firmware_file]
        if not verbose:
            cmd.append('--quiet')
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if verbose:
            logger.info(f"Binwalk output: {result.stdout}")
        
        # Binwalk 2.1.0 outputs to _filename.extracted
        extracted_path = f"_{firmware_file}.extracted"
        if os.path.exists(extracted_path):
            # Move squashfs-root if present, otherwise move entire extracted dir
            squashfs_root = os.path.join(extracted_path, 'squashfs-root')
            if os.path.exists(squashfs_root):
                os.rename(squashfs_root, extracted_dir)
                if cleanup:
                    subprocess.run(['rm', '-rf', extracted_path], check=False)
            else:
                os.rename(extracted_path, extracted_dir)
            logger.info("Extraction successful with binwalk")
            return extracted_dir
        else:
            logger.warning("Binwalk ran but no extracted directory found")
    except subprocess.CalledProcessError as e:
        logger.warning(f"Binwalk extraction failed: {e.stderr}")
    except Exception as e:
        logger.warning(f"Binwalk error: {e}")

    # Fallback to 7zip
    try:
        subprocess.run(['7z', '-h'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        logger.info(f"Attempting extraction with 7zip for {firmware_file}")
        subprocess.run(['7z', 'x', firmware_file, f'-o{extracted_dir}', '-y'], check=True)
        logger.info("Extraction successful with 7zip")
        return extracted_dir
    except FileNotFoundError:
        logger.warning("7zip not found in PATH. Skipping.")
    except subprocess.CalledProcessError as e:
        logger.warning(f"7zip extraction failed: {e}")

    # Fallback to manual extraction (unlikely for DVRF)
    try:
        logger.info(f"Attempting manual extraction for {firmware_file}")
        os.makedirs(extracted_dir, exist_ok=True)
        if firmware_file.endswith('.tar.gz') or firmware_file.endswith('.tgz'):
            subprocess.run(['tar', 'xzf', firmware_file, '-C', extracted_dir], check=True)
        elif firmware_file.endswith('.tar'):
            subprocess.run(['tar', 'xf', firmware_file, '-C', extracted_dir], check=True)
        elif firmware_file.endswith('.zip'):
            subprocess.run(['unzip', '-o', firmware_file, '-d', extracted_dir], check=True)
        else:
            logger.warning("No recognizable archive format for manual extraction")
            raise ValueError("Unsupported format")
        logger.info("Manual extraction successful")
        return extracted_dir
    except Exception as e:
        logger.warning(f"Manual extraction failed: {e}")

    logger.error(f"All extraction methods failed for {firmware_file}")
    return None

if __name__ == "__main__":
    # For standalone testing
    firmware_file = "samples/DVRF/Firmware/DVRF_v03.bin"
    extract_firmware(firmware_file, verbose=True, overwrite=True, cleanup=False)