#!/bin/bash

if [ ! -f /usr/local/bin/dialog ]; then
	exit 1 # Dialog is not installed
fi

##
# Defaults
##
JSONFile=$(mktemp -u /var/tmp/dialogJSONFile.XXX)
commandFile=$(mktemp -u /var/tmp/dialogCommandFile.XXX)
scriptVersion="1.0.1"

loggedInUser=$(stat -f%Su /dev/console)
# dont display other users if we are not woodmin|tokenadmin
if [[ "${loggedInUser}" =~ ^(woodmin|tokenadmin)$ ]]; then
	userHomesRaw=$(ls -d /Users/*/ | grep -vE '(Shared|tokenadmin)' | xargs -n 1 basename | paste -sd "," -)
else
	userHomesRaw="${loggedInUser}"
fi
userHomes=$(echo "${userHomesRaw}" | tr ',' '\n' | sort -f | uniq | sed -e 's/^/\"/' -e 's/$/\",/' -e '$ s/.$//')

##
# Functions
##

function dialogUpdate() {
	echo "${1}" >>"$commandFile"
}

# https://github.com/dan-snelson/Setup-Your-Mac/blob/465074f8f5eff793270534ed2e9d4e6c96b00ab9/Setup-Your-Mac-via-Dialog.bash#L1765-L1772
function get_json_value() {
	# set -x
	for var in "${@:2}"; do jsonkey="${jsonkey}['${var}']"; done
	JSON="$1" osascript -l 'JavaScript' \
		-e 'const env = $.NSProcessInfo.processInfo.environment.objectForKey("JSON").js' \
		-e "JSON.parse(env)$jsonkey"
	# set +x
}

function clean_quit() {
	code=${1}
	rm -f "${JSONFile}"
	rm -f "${commandFile}"
	exit "${code}"
}

function refresh_files() {
	echo "" >"${JSONFile}"
	echo "" >"${commandFile}"
}

bytesToHuman() {
	b=${1:-0}
	d=''
	s=0
	S=(Bytes KB MB GB TB PB EB ZB YB)
	while ((b > 1000)); do
		d="$(printf ".%02d" $((b % 1000 * 100 / 1000)))"
		b=$((b / 1000))
		((s++))
	done
	echo "$b$d ${S[$s]}"
}

# ================================
# Title: List External Disks
# Description: This function lists all external disks that match specific partition types on macOS.
# ================================

function listDisks() {
	echo "Listing external disks"

	# Define a list of acceptable partition types
	declare -a acceptablePartitionTypes=("Apple_HFS" "APFS" "Microsoft Basic Data")

	# Get a list of all physical disk identifiers
	diskList=$(diskutil list | grep '^/dev/' | awk '{print $1}')

	# Initialize an array to hold formatted output
	declare -a formattedVolumes

	# Iterate over each disk
	for disk in ${diskList}; do
		# Get information about each partition or APFS volume in the disk
		partitionInfo=$(diskutil list "${disk}" | grep -E '^[ ]*\d\:|APFS Volume' | awk '{print $NF}')

		# Iterate over each partition or APFS volume
		while read -r partition; do
			# Store the output of diskutil info for the partition or APFS volume
			partitionDetails=$(diskutil info "${partition}")

			# Determine if the partition is APFS
			isAPFS=$(echo "${partitionDetails}" | grep 'Type (Bundle):' | grep -i 'apfs')

			# Select 'Partition Type' or 'File System Personality' based on whether it's APFS
			if [ -n "$isAPFS" ]; then
				partitionType=$(echo "${partitionDetails}" | grep 'File System Personality:' | cut -d ':' -f2 | xargs)
			else
				partitionType=$(echo "${partitionDetails}" | grep 'Partition Type:' | cut -d ':' -f2 | xargs)
			fi

			# Fetch other partition details
			deviceLocation=$(echo "${partitionDetails}" | grep 'Device Location:' | cut -d ':' -f2 | xargs)
			isMounted=$(echo "${partitionDetails}" | grep 'Mounted:' | cut -d ':' -f2 | xargs)
			mountPoint=$(echo "${partitionDetails}" | grep 'Mount Point:' | cut -d ':' -f2 | xargs)

			# Check conditions for acceptable partition type, external location, mount status, and mount point
			if [[ "$deviceLocation" == "External" && " ${acceptablePartitionTypes[*]} " =~ ${partitionType} && "${isMounted}" == "Yes" && "${mountPoint}" == /Volumes/* ]]; then
				volumeName=$(echo "${partitionDetails}" | grep 'Volume Name:' | cut -d ':' -f2 | xargs)
				volumeDevice=$(echo "${partitionDetails}" | grep 'Device Identifier:' | cut -d ':' -f2 | xargs)

				# Add formatted volume name and device to the array
				formattedVolumes+=("\"${volumeName} (${volumeDevice})\"")
			fi
		done <<<"$partitionInfo"
	done

	# Output the formatted list of external disks
	if [ ${#formattedVolumes[@]} -eq 0 ]; then
		echo "No external disks found."
	else
		echo "External disks found. Preparing list."
		printf -v volumeList "%s," "${formattedVolumes[@]}"
		echo "${volumeList%,}"
	fi
}

# ================================
# Title: Get Disk Mount Point
# Description: This function retrieves the mount point of a specified disk using diskutil on macOS.
# ================================

function get_mount_point() {
	# Retrieve mount point information using diskutil
	# $1 is expected to be the disk identifier
	echo "Retrieving mount point for disk: $1"
	mount=$(diskutil info "${1}" | grep 'Mount Point:' | cut -d ':' -f2 | xargs)

	# Check if the command was successful
	if [ "$?" -eq 0 ] && [ -n "${mount}" ]; then
		echo "Mount point found: ${mount}"
		destination="${mount}"
	else
		echo "No mount point found for disk: ${1}"
		destination=""
	fi
}

# ================================
# Title: Backeruper Source/Destination Selection Dialog
# Description: This function creates and manages a dialog for selecting the user and destination for backup.
# ================================

function source_destination_dialog() {
	# List available disks
	echo "Listing available disks for backup destination."
	listDisks

	# Prepare JSON for the dialog
	echo "Preparing source and destination selection dialog."
	if [ -z "${volumeList}" ]; then
		destinationDefault="No External Drives Attached"
		volumeList='"No External Drives Attached"'
		button1text="Next"
		button1disabled="true"
	else
		destinationDefault="${volumeList%%,*}"
		button1text="Next"
		button1disabled="false"
	fi

	dialogJSON='{
      "title": "Backeruper",
      "message": "This utility helps backup your files to an external drive.  \nHere you can select which user to backup, and the destination drive.",
      "icon": "sf=externaldrive.fill.badge.person.crop",
      "button1text": "'"${button1text}"'",
      "button2text": "Cancel",
      "selectitems": [
        {
          "title": "User",
          "default": "'"${loggedInUser}"'",
          "required": true,
          "values": ['"${userHomes}"']
        },
        {
          "title": "Destination",
          "default": "'"${destinationDefault//[\'\"]/}"'",
          "required": true,
          "values": ['"${volumeList}"']
        }
      ],
      "blurscreen": "false",
	  "infotext": "'"${scriptVersion}"'",
      "ontop": "false",
      "moveable": "true",
      "quitkey": ".",
      "height": "325",
      "width": "650"
    }'

	# Display the Dialog
	refresh_files
	echo "${dialogJSON}" >"${JSONFile}"
	echo "Displaying source and destination selection dialog."
	results=$(eval dialog --jsonfile "${JSONFile}" --json "$([ "${button1disabled}" = "true" ] && echo " --button1disabled") ") # display dialog

	# Evaluate User Input
	if [[ -z "${results}" ]]; then
		returnCode="2"
	else
		returnCode="0"
	fi

	# Handle User Selections
	case "${returnCode}" in
	0) # User pressed 'Next'
		echo "User pressed 'Next'. Processing selections."
		# Display a processing dialog
		dialog --icon "sf=gearshape.fill,animation=pulse" --mini --title "Backeruper" --message "Gathering Intelligence" --progress &
		sleep 0.3
		until pgrep -q -x "Dialog"; do
			sleep 0.5
		done

		# Parse selections
		selectedUser=$(get_json_value "${results}" "User" "selectedValue")
		selectedDestination=$(get_json_value "${results}" "Destination" "selectedValue")
		;;
	*) # User pressed 'Cancel' or closed the dialog
		echo "User cancelled the selection."
		clean_quit 0
		;;
	esac
}

# ================================
# Title: Backeruper Folder Selection Dialog
# Description: This section of the script creates a dialog for selecting folders to backup.
# ================================

function folder_select_dialog() {

	# Initialise Folder Selection Dialog
	# -----------------------------------
	# Define an array of folder names for selection
	folders=("Desktop" "Documents" "Downloads" "Pictures" "Movies" "Music" "OneDrive")

	# Start building the dialog JSON
	dialogJSON='{
  "commandfile": "'"${commandFile}"'",
  "title": "Backeruper",
  "message": "Please select the data you would like to backup.",
  "icon": "sf=externaldrive.fill.badge.questionmark",
  "button1text": "Backup",
  "button2text": "Cancel",
  "infotext": "'"${scriptVersion}"'",
  "checkbox": ['

	# Loop through folders to add them to the dialog
	echo "Adding folders to selection dialog."
	infoboxContent+="**Source Info:**  \n"
	for folder in "${folders[@]}"; do
		# Check if the folder exists and get its size
		if [ -d "/Users/${selectedUser}/${folder}" ]; then
			disabled="false"
			folderSize=$(du -sh "/Users/${selectedUser}/${folder}" | cut -f1)
			infoboxContent+="**${folder}:** ${folderSize}B  \n"
		else
			disabled="true"
		fi

		# Add checkbox entry for the folder
		dialogJSON+='{
      "label": "'"${folder}"'",
      "checked": "false",
      "disabled": "'"${disabled}"'"
    },'
	done

	# Finalise the dialog JSON
	# Remove the last comma from checkbox entries and complete the JSON structure
	dialogJSON=$(echo "${dialogJSON}" | sed '$ s/,$//')
	dialogJSON+='],
  "checkboxstyle": {
    "style": "switch",
    "size": "regular"
  },
  "infobox": "'"${infoboxContent}"'",
  "blurscreen": "false",
  "ontop": "false",
  "moveable": "true",
  "quitkey": ".",
  "height": "450",
  "width": "725"
}'

	# Display the Dialog
	# -------------------
	# Terminate any existing Dialog processes
	killall Dialog &>/dev/null
	refresh_files
	echo "${dialogJSON}" >"${JSONFile}"

	# Display the dialog and capture the results
	echo "Displaying folder selection dialog."
	results=$(eval dialog --jsonfile "${JSONFile}" --json) # display dialog

	# Evaluate User Input
	# --------------------
	if [[ -z "${results}" ]]; then
		returnCode="2"
	else
		returnCode="0"
	fi

	case "${returnCode}" in
	0) # User selected 'Backup'
		echo "User selected 'Backup'."
		;;
	*) # User selected 'Cancel' or closed the dialog
		echo "User selected 'Cancel' or closed the dialog."
		clean_quit 0
		;;
	esac
}
# ================================
# Title: Backeruper Destination Selection and Validation
# Description: This section of the script handles the selection of backup destination and validates it.
# ================================
# Invoke Dialog for Source and Destination Selection
# ---------------------------------------------------
echo "Invoking source and destination selection dialog."
source_destination_dialog

# Validate Selected User and Destination
# --------------------------------------
# Extract the destination path from the selected destination
destination=$(echo "${selectedDestination}" | awk -F'[()]' '{print $(NF-1)}')

# Check if selected user is empty
if [ -z "${selectedUser}" ]; then
	echo "No user selected. Exiting."
	clean_quit 1
fi

# Check if selected destination is empty
if [ -z "${selectedDestination}" ]; then
	echo "No destination selected. Exiting."
	clean_quit 1
else
	# Get partition name
	parttype=$(diskutil info "${destination}" | grep 'Name (User Visible):' | cut -d ':' -f2 | xargs)
	# Retrieve the mount point of the destination
	get_mount_point "${destination}" # overwrites destination variable
fi

# Disk Speed Test
# ----------------
echo "Performing disk speed test on the selected drive."
# Perform a speed test on the drive
diskSpeed=$(dd if=/dev/zero of="${destination}"/testfile bs=1M count=128 oflag=direct 2>&1 | grep -o '[0-9]\+ bytes/sec' | awk '{print $1}')
# Clean up the test file
rm -f "${destination}"/testfile
# Convert the speed to a human-readable format
diskSpeed="$(bytesToHuman "${diskSpeed}")"

# Add disk speed info to the infobox content
infoboxContent="**Destination Info:**  \n**Speed:** ${diskSpeed}/s  \n**Type**: ${parttype}\n\n"

echo "Disk speed test completed: ${diskSpeed}/s."

folder_select_dialog

# ================================
#
# we need to add a size check here!
#
# ================================

# ================================
# Title: Progression Dialog
# Description: Handles the progression dialog
# ================================

# Initialise and Display Progress Dialog
# ---------------------------------------
# Command for showing the progress dialog
dialogProgressCMD="dialog \
--title 'Backeruper' \
--message 'This could take a while... Please be patient.' \
--icon 'sf=externaldrive.fill.badge.timemachine' \
--infobox \"${infoboxContent}\" \
--progress \
--moveable \
--progresstext \"Initialising configuration\" \
--button1text \"Wait\" \
--button1disabled \
--infotext \"$scriptVersion\" \
--height '500' \
--quitkey k \
--commandfile \"${commandFile}\" "

# Execute the dialog command
eval "${dialogProgressCMD[*]}" &
sleep 0.3

# Wait for 'Dialog' process to start
until pgrep -q -x "Dialog"; do
	sleep 0.5
done
echo "Progress dialog initialised."

# Create Destination Directory
# -----------------------------
echo "Creating destination directory for user ${selectedUser}."
mkdir -p "${destination}/${selectedUser}"

# Initialise Rsync Failure Flag
# -----------------------------
# Flag to track if rsync fails during execution
rsync_failed=0

# Prepare List of Folders
# ------------------------
# Generate a CSV list of folders to be processed
echo "Generating list of folders for processing."
folderListCsv=""
index=0
for folder in "${folders[@]}"; do
	if [[ $(get_json_value "${results}" "${folder}") == "true" ]]; then
		folderListCsv+="${folder},"
		dialogUpdate "listitem: index: ${index}, status: pending, statustext: Pending"
		((index++))
	fi
done

# Trim the trailing comma from the CSV list
folderListCsv=${folderListCsv%,}

# Initialise Dialog List
# -----------------------
dialogUpdate "list: ${folderListCsv}"
dialogUpdate "list: show"
progressIncrementValue=$((100 / index))
index=0 # Reset index for processing loop

case "${parttype}" in

APFS)
	echo "Drive supports extended attributes, using -avtE"
	rsyncArgs="-avtE"
	;;
Mac\ OS\ Extended\ \(Journaled\))
	echo "Drive supports extended attributes, using -avtE"
	rsyncArgs="-avtE"
	;;
*)
	echo "Drive does not support extended attributes! using -avt"
	rsyncArgs="-avt"
	;;
esac

# Processing Each Folder
# ----------------------
echo "Starting folder processing."
dialogUpdate "progress: 1"
for folder in "${folders[@]}"; do
	if [[ $(get_json_value "${results}" "${folder}") == "true" ]]; then
		dialogUpdate "listitem: index: ${index}, status: wait, statustext: Processing"
		sleep 1
		# Run rsync for each folder
		rsync "${rsyncArgs}" --delete --out-format="%n" "/Users/${selectedUser}/${folder}/" "${destination}/${selectedUser}/${folder}" 2>&1 |
			while IFS= read -r file; do
				if [[ -n "$file" ]]; then
					dialogUpdate "progresstext: ${file}"
				fi
			done

		# Capture the rsync exit status
		rsync_status=${PIPESTATUS[0]}

		# Update Dialog based on rsync result
		if [ "${rsync_status}" -eq 0 ]; then
			dialogUpdate "listitem: index: ${index}, status: success, statustext: Done!"
		else
			dialogUpdate "listitem: index: ${index}, status: fail, statustext: Failed!"
			rsync_failed=1
		fi

		# Increment index and update progress
		((index++))
		dialogUpdate "progress: increment ${progressIncrementValue}"
	fi
done

# Final Dialog Update
# -------------------
echo "Finalising the process."
if [ ${rsync_failed} -eq 0 ]; then
	dialogUpdate "progresstext: Completed Successfully!"
	dialogUpdate "icon: sf=externaldrive.fill.badge.checkmark"
	dialogUpdate "progress: complete"
else
	dialogUpdate "icon: sf=externaldrive.fill.badge.xmark"
	dialogUpdate "progress: reset"
fi

# Enable 'Close' Button
dialogUpdate "button1text: Close"
dialogUpdate "button1: enable"
sleep 1

# Exit Script
echo "Script execution completed."
clean_quit 0
