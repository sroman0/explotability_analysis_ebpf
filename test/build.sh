#!/usr/bin/env bash

# build.sh - Automate buildroot configuration selection per CVE and kernel version

set -euo pipefail
IFS=$'\n\t'

# Constants
declare -r DEV_PATH="$PWD"
declare -r BUILDROOT_PATH="$DEV_PATH/buildroot"
declare -r DEFAULT_CONFIG_FILE=".config"
declare -r CVE_DIR="$DEV_PATH/CVEs"
declare -r PATCHES_DIR="$DEV_PATH/patches"

# Ensure necessary directories exist
if [[ ! -d "$CVE_DIR" ]]; then
    echo "Error: CVEs directory not found at $CVE_DIR"
    exit 1
fi
if [[ ! -d "$BUILDROOT_PATH" ]]; then
    echo "Error: buildroot directory not found at $BUILDROOT_PATH"
    exit 1
fi

# Delete old files inside old rootfs_overlay
old_config="$BUILDROOT_PATH/.config.old"
build_dir="$BUILDROOT_PATH/output/build"
target_dir="$BUILDROOT_PATH/output/target"

if [[ -f "$old_config" ]]; then
    echo "Found old config, cleaning up previous overlay files..."
    
    # Extract old overlay path
    old_overlay_relative=$(grep -o 'BR2_ROOTFS_OVERLAY="[^"]*"' "$old_config" 2>/dev/null | cut -d'"' -f2 || echo "")
    old_overlay="$BUILDROOT_PATH/$old_overlay_relative"

    if [[ -n "$old_overlay_relative" && -d "$old_overlay" ]]; then
        echo "Cleaning files from old overlay: $old_overlay"
        
        # Find all items in old overlay (files and directories at top level)
        cd "$old_overlay" || exit 1
        find . -maxdepth 1 -not -name '.' -print0 | while IFS= read -r -d '' item; do
            # Remove leading ./ from path
            relative_path="${item#./}"
            target_item="$target_dir/$relative_path"
            
            if [[ -e "$target_item" ]]; then
                echo "Removing old overlay item: $target_item"
                rm -rf "$target_item"
            fi
        done
        
        cd "$DEV_PATH" # Return to original directory
        echo "Old overlay cleanup completed"
    else
        echo "No valid old overlay directory found or overlay path empty"
    fi

    # Delete old CVE package
    dir=""
    if [[ -d "$build_dir" ]]; then
        dir=$(find "$build_dir" -maxdepth 1 -type d -name 'CVE-*' | head -n 1)
    fi
    if [ -n "$dir" ]; then
        folder_name=$(basename "$dir")
        echo "Deleting directory: $folder_name"
        rm -rf "$dir"
        echo "Deleting command"
        rm -f $target_dir/usr/bin/cve-*
    fi
else
    echo "No old config found, skipping overlay cleanup"
fi

# Build CVE menu options dynamically
cve_list=($(ls "$CVE_DIR" | grep -v -E '^(Config.in|external\.desc|external\.mk)$'))
if [[ ${#cve_list[@]} -eq 0 ]]; then
    echo "No CVE directories found in $CVE_DIR"
    exit 1
fi

menu_items=()
for cve in "${cve_list[@]}"; do
    menu_items+=("$cve" "")
done

# Prompt user to select a CVE
selected_cve=$(whiptail --title "Select a CVE" --menu \
    "Choose the CVE exploit to configure:" 25 65 ${#cve_list[@]} \
    "${menu_items[@]}" 3>&1 1>&2 2>&3) || exit 1

# Path to configs for selected CVE
configs_path="$CVE_DIR/$selected_cve/configs"
if [[ ! -d "$configs_path" ]]; then
    echo "Error: configs directory not found for $selected_cve"
    exit 1
fi

# Build kernel-version menu for selected CVE
kernels=($(ls -d "$configs_path"/v* | xargs -n1 basename))
if [[ ${#kernels[@]} -eq 0 ]]; then
    echo "No kernel configurations found for $selected_cve"
    exit 1
fi

def_menu=()
for kv in "${kernels[@]}"; do
    def_menu+=("$kv" "")
done

selected_kernel=$(whiptail --title "Select kernel version" --menu \
    "Choose the kernel version to configure for $selected_cve:" 25 65 16 \
    "${def_menu[@]}" 3>&1 1>&2 2>&3) || exit 1

echo "Selected: CVE=$selected_cve, Kernel=$selected_kernel"

# Prepare the buildroot .config
target_config_src="$configs_path/$selected_kernel/buildroot.config"
target_config_dst="$BUILDROOT_PATH/$DEFAULT_CONFIG_FILE"

if [[ ! -f "$target_config_src" ]]; then
    echo "Error: buildroot.config not found at $target_config_src"
    exit 1
fi

# Copy the selected config
rm -f "$target_config_dst"
cp "$target_config_src" "$target_config_dst"

# Apply patch entry if available
# Strip leading 'v' from version
kernel_ver_no_v="${selected_kernel#v}"
patch_dir="$PATCHES_DIR/linux-$kernel_ver_no_v"
if [[ -d "$patch_dir" ]]; then
    sed -i 's|^BR2_LINUX_KERNEL_PATCH="[^"]*"|BR2_LINUX_KERNEL_PATCH="'"$patch_dir"'"|' "$target_config_dst"
    echo "Applied patch directory: $patch_dir"
else
    echo "No patch directory for kernel $kernel_ver_no_v"
fi

# Automate setting custom kernel config, overlay and users table
# Paths relative to buildroot
custom_config="../CVEs/$selected_cve/configs/$selected_kernel/kernel.config"
overlay_dir="../CVEs/$selected_cve/exploit_overlay"
users_table="../CVEs/$selected_cve/configs/user_table.txt"

# Update or add the entries
sed -i 's|^BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE=.*|BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE="'"$custom_config"'"|' "$target_config_dst"
sed -i 's|^BR2_ROOTFS_OVERLAY=.*|BR2_ROOTFS_OVERLAY="'"$overlay_dir"'"|' "$target_config_dst"
# Only set users table if file exists
if [[ -f "$configs_path/user_table.txt" ]]; then
    sed -i 's|^BR2_ROOTFS_USERS_TABLES=.*|BR2_ROOTFS_USERS_TABLES="'"$users_table"'"|' "$target_config_dst"
    echo "Set users table: $users_table"
else
    echo "No user_table.txt for $selected_cve, skipping users table setting"
fi

# Final message
echo "Buildroot configuration prepared in $BUILDROOT_PATH"

cd $BUILDROOT_PATH
make linux-dirclean     # Note: this fix is needed when I want to build a kernel that has been previously compiled
                        #       otherwise buildroot skips the compilation and the OS has the previous kernel and
                        #       not the selected one

# Strip legacy options from .config to avoid "You have legacy configuration" errors.
# When buildroot is updated, previously valid options may move to Config.in.legacy
# and set BR2_LEGACY=y, causing the build to fail. We remove them so that
# make olddefconfig can replace them with current defaults automatically.
echo "Stripping legacy options from .config..."
legacy_opts=$(grep -E "^config BR2_" "$BUILDROOT_PATH/Config.in.legacy" | awk '{print $2}')
for opt in $legacy_opts; do
    sed -i "/^${opt}=.*/d" "$BUILDROOT_PATH/.config"
    sed -i "/^# ${opt} is not set/d" "$BUILDROOT_PATH/.config"
done
echo "Legacy options stripped."

make olddefconfig       # Silently accept default values for any new/unknown options
make

