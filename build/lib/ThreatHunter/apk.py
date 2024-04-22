import zipfile
import shutil
import os
from apktools import APK


'''APK files contain metadata about the application,
such as the package name, version, and minimum SDK version'''


def get_apk_metadata(file_path):
    try:
        apk = APK(file_path)
        print(f"Package name: {apk.manifest.package}")
        print(f"Version code: {apk.manifest.versionCode}")
        print(f"Version name: {apk.manifest.versionName}")
        print(f"Minimum SDK version: {apk.manifest.minSdkVersion}")
    except Exception as e:
        print(f"Error parsing APK file: {e}")


'''describe the application's user interface components,
such as activities and services.'''


def get_apk_activities(file_path):
    try:
        apk = APK(file_path)
        for activity in apk.activities:
            print(f"Activity name: {activity.name}")
            print(f"Activity label: {activity.label}")
            print(f"Activity intent filters: {activity.intentFilters}")
    except Exception as e:
        print(f"Error parsing APK file: {e}")


'''Permissions in APK files describe the application's
access to sensitive resources, such as camera, location, and contacts'''


def get_apk_permissions(file_path):
    try:
        apk = APK(file_path)
        for permission in apk.permissions:
            print(f"Permission name: {permission.name}")
            print(f"Permission protection level: {permission.protectionLevel}")
    except Exception as e:
        print(f"Error parsing APK file: {e}")


'''Resources in APK files contain additional data, such as icons,
layouts, and strings'''


def get_apk_resources(file_path):
    try:
        apk = APK(file_path)
        for resource in apk.resources:
            print(f"Resource name: {resource.name}")
            print(f"Resource type: {resource.type}")
            print(f"Resource size: {resource.size}")
    except Exception as e:
        print(f"Error parsing APK file: {e}")


def extract_info(filepath):
    # Extract the manifest and resources
    with zipfile.ZipFile(filepath, 'r') as zip_archive:
        manifest = zip_archive.read('AndroidManifest.xml').decode("utf-8")
        resources_dir = 'resources/'

        # Create a directory for resources
        if not os.path.exists(resources_dir):
            os.makedirs(resources_dir)

        # Skip the manifest and META-INF folders
        for item in zip_archive.namelist()[1:-1]:
            if not item.endswith('/'):
                continue
            filename = item[:-1] + '/' + item[-1]
            out_path = os.path.join(resources_dir, filename)
            with zip_archive.open(item) as f:
                shutil.copyfileobj(f, open(out_path, 'wb'))

    return manifest, resources_dir


if __name__ == "__main__":
    # Replace 'your_app.apk' with the path to your APK file
    filepath = 'your_app.apk'
    manifest, resources_dir = extract_info(filepath)

    print("\nManifest:\n", manifest)
    print("\nResources saved to:", resources_dir)