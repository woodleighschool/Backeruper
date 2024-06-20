#!/bin/bash

# ================================
# Defaults
# ================================
JSONFile=$(mktemp -u /var/tmp/dialogJSONFile.XXX)
commandFile=$(mktemp -u /var/tmp/dialogCommandFile.XXX)
scriptVersion="1.0.1"

# ================================
# Compatibility checks (dialog installed, rsync compatible)
# ================================
if [ ! -f /usr/local/bin/dialog ]; then
	exit 1 # Dialog is not installed
fi

# native macos rsync does not have some flags we need
if [ ! -f "/usr/local/bin/rsync" ]; then
	curl -L https://r2-d2.woodleigh.vic.edu.au/Packages/rsync-3.3.0.pkg -o /var/tmp/rsync-3.3.0.pkg
	installer -pkg /var/tmp/rsync-3.3.0.pkg -target /
	rm /var/tmp/rsync-3.3.0.pkg
fi

# ================================
# Autopopulate fields
# ================================
# logged in user for home selection default
loggedInUser=$(stat -f%Su /dev/console)

# Don't display other users if we are not woodmin|tokenadmin
if [[ "${loggedInUser}" =~ ^(woodmin|tokenadmin)$ ]]; then
	# find all user homes in /Users, return as comma seperated
	userHomesRaw=$(ls -d /Users/*/ | grep -vE '(Shared|tokenadmin)' | xargs -n 1 basename | paste -sd "," -)
else
	# return the logged in user if we are not allowed to backup other users' home
	userHomesRaw="${loggedInUser}"
fi
userHomes=$(echo "${userHomesRaw}" | tr ',' '\n' | sort -f | uniq | sed -e 's/^/\"/' -e 's/$/\",/' -e '$ s/.$//')

# Define an array of subdirectories to exclude, relative to /Users/${selectedUser}
excludePatterns=("Library/Audio" "Library/Autosave Information" "Library/CallServices" "Library/CloudStorage" "Library/Cookies" "Library/Favorites" "Library/GameKit" "Library/GroupContainersAlias" "Library/Log" "Library/Maps" "Library/NGL" "Library/News" "Library/PhotoshopCrashes" "Library/Printers" "Library/SafariSafeBrowsing" "Library/ScreenRecordings" "Library/Staging" "Library/SyncedPreferences" "Library/Contacts" "Library/ContainerManager" "Library/DataAccess" "Library/LaunchAgents" "Library/LockdownMode" "Library/Reminders" "Library/SafariSandboxBroker" "Library/com.amplitude.plist" "Library/DataDeliveryServices" "Library/MobileDevice" "Library/ResponseKit" "Library/studentd" "Library/Google" "Library/Translation" "Library/com.apple.bluetoothuser" "Library/CoreFollowUp" "Library/Sharing" "Library/com.amplitude.database" "Library/Application Scripts" "Library/com.apple.bluetooth.services.cloud" "Library/org.swift.swiftpm" "Library/Keyboard" "Library/UnifiedAssetFramework" "Library/DoNotDisturb" "Library/Intents" "Library/DES" "Library/KeyboardServices" "Library/com.apple.internal.ck" "Library/LanguageModeling" "Library/com.apple.AppleMediaServices" "Library/com.apple.icloud.searchpartyd" "Library/com.apple.iTunesCloud" "Library/Accessibility" "Library/com.apple.groupkitd" "Library/Saved Application State" "Library/Accounts" "Library/FrontBoard" "Library/Passes" "Library/Shortcuts" "Library/com.apple.aiml.instrumentation" "Library/Assistant" "Library/AppleMediaServices" "Library/IdentityServices" "Library/com.apple.appleaccountd" "Library/WebKit" "Library/Calendars" "Library/Finance" "Library/Trial" "Library/PersonalizationPortrait" "Library/Weather" "Library/Suggestions" "Library/StatusKit" "Library/Safari" "Library/DuetExpertCenter" "Library/HomeKit" "Library/Daemon Containers" "Library/IntelligencePlatform" "Library/Logs" "Library/Keychains" "Library/Preferences" "Library/HTTPStorages" "Library/Mobile Documents" "Library/Biome" "Library/Metadata" "Library/Mail" "Library/Developer" "Library/Photos" "Library/Caches" "Library/Containers" "Library/Group Containers" "Library/iTunes" "Library/Python")

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

convert_to_bytes() {
	local totalSize=0
	local unit
	local number

	for size in "$@"; do
		# Extract the number and the unit (if any)
		number=$(echo $size | sed -E 's/([0-9.]+)([KMGTP]?)B?/\1/')
		unit=$(echo $size | sed -E 's/([0-9.]+)([KMGTP]?)B?/\2/')

		# Convert the size to bytes based on the unit
		case $unit in
		K) number=$(echo "$number * 1000" | bc | awk '{print int($1+0.5)}') ;;
		M) number=$(echo "$number * 1000^2" | bc | awk '{print int($1+0.5)}') ;;
		G) number=$(echo "$number * 1000^3" | bc | awk '{print int($1+0.5)}') ;;
		T) number=$(echo "$number * 1000^4" | bc | awk '{print int($1+0.5)}') ;;
		P) number=$(echo "$number * 1000^5" | bc | awk '{print int($1+0.5)}') ;;
		*) number=$(echo "$number" | bc | awk '{print int($1+0.5)}') ;; # No unit means bytes
		esac

		# Add to the total
		totalSize=$(echo "$totalSize + $number" | bc)
	done

	# Convert total to an integer to avoid decimals
	echo $(echo "$totalSize" | awk '{print int($1+0.5)}')
}

function updateScriptLog() {
	echo -e "$(date +%Y-%m-%d\ %H:%M:%S) - ${1}" # | tee -a "${scriptLog}"
}

# ================================
# Title: List External Disks
# Description: This function lists all external disks that match macos supported partitions.
# ================================

function listDisks() {
	set -x
	updateScriptLog "Listing external disks"

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
		updateScriptLog "No external disks found."
	else
		updateScriptLog "External disks found. Preparing list."
		printf -v volumeList "%s," "${formattedVolumes[@]}"
		updateScriptLog "${volumeList%,}"
	fi
	set +x
}

# ================================
# Retrieves the mount point of a disk using diskutil
# ================================
function get_mount_point() {
	# $1 is expected to be the disk identifier
	updateScriptLog "Retrieving mount point for disk: $1"
	mount=$(diskutil info "${1}" | grep 'Mount Point:' | cut -d ':' -f2 | xargs)

	# Check if the command was successful
	if [ "$?" -eq 0 ] && [ -n "${mount}" ]; then
		updateScriptLog "Mount point found: ${mount}"
		destination="${mount}/Backeruper"
	else
		updateScriptLog "No mount point found for disk: ${1}"
		destination=""
	fi
}

toBackupFolder() {
	# Extract the line containing the folder name
	local line=$(echo "${results}" | grep "\"${folder}")

	# Check if the line contains "true"
	if [[ "${line}" =~ "true" ]]; then
		return 0
	else
		return 1
	fi
}

# ================================
# Title: Backeruper Source/Destination Selection Dialog
# Description: This function creates and manages a dialog for selecting the user and destination for backup.
# ================================

function source_destination_dialog() {
	# List available disks
	updateScriptLog "Listing available disks for backup destination."
	listDisks

	# Prepare JSON for the dialog
	updateScriptLog "Preparing source and destination selection dialog."
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
	updateScriptLog "Displaying source and destination selection dialog."
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
		updateScriptLog "User pressed 'Next'. Processing selections."
		# Display a processing dialog
		dialog --icon "sf=gearshape.fill,animation=pulse" --mini --title "Backeruper" --message "Gathering Intelligence" --progress --commandfile "${commandFile}" &
		sleep 0.3
		until pgrep -q -x "Dialog"; do
			sleep 0.5
		done

		# Parse selections
		selectedUser=$(get_json_value "${results}" "User" "selectedValue")
		selectedDestination=$(get_json_value "${results}" "Destination" "selectedValue")
		;;
	*) # User pressed 'Cancel' or closed the dialog
		updateScriptLog "User cancelled the selection."
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

	folders=()

	# Use a loop to read folder names line by line
	while IFS= read -r folder; do
		# Skip the selectedUser folder and .Trash
		if [[ ! "$folder" =~ (${selectedUser}|\.Trash) ]]; then
			folders+=("$folder")
		fi
	done < <(find "/Users/${selectedUser}" -type d -maxdepth 1 -exec basename {} \; | sort -d)

	# Start building the dialog JSON
	dialogJSON='{
  "commandfile": "'"${commandFile}"'",
  "title": "Backeruper",
  "message": "Please select the folders you would like to backup.",
  "icon": "sf=externaldrive.fill.badge.questionmark",
  "button1text": "Backup",
  "button2text": "Cancel",
  "infotext": "'"${scriptVersion}"'",
  "checkbox": ['

	# Loop through folders to add them to the dialog
	updateScriptLog "Adding folders to selection dialog."

	for folder in "${folders[@]}"; do
		dialogUpdate "progresstext: Indexing: /Users/${selectedUser}/${folder}"

		# Initialize the array for du command
		duCommand=(du -ch)
		for exc in "${excludePatterns[@]}"; do
			# Extract the top-level folder name from the exclusion pattern
			topLevelFolder=$(echo "${exc}" | cut -d'/' -f1)
			# Check if the current folder matches the top-level folder in the exclusion pattern
			if [[ "${folder}" == "${topLevelFolder}" ]]; then
				# Extract the bottom-level folder name and append to du command array
				bottomLevelFolder=$(basename "${exc}")
				duCommand+=(-I "${bottomLevelFolder}")
			fi
		done

		# Calculate the total size with the specified exclusions
		folderSize=$("${duCommand[@]}" "/Users/${selectedUser}/${folder}" | tail -n1 | cut -f1)
		# keep a total for later
		folderSizesArray+=("${folderSize}")
		# some folders should be pre-checked
		case "${folder}" in
		Desktop)
			checked="true"
			;;
		Documents)
			checked="true"
			;;
		Downloads)
			checked="true"
			;;
		Pictures)
			checked="true"
			;;
		*[wW]oodleigh*) # for onedrive
			checked="true"
			;;
		*)
			checked="false"
			;;
		esac

		# Add checkbox entry for the folder
		dialogJSON+='{
      "label": "'"${folder}"' ('"${folderSize// /}"')",
      "checked": "'"${checked}"'",
      "disabled": "false"
    },'
	done
	set -x
	# Finalise the dialog JSON
	totalSizeInBytes=$(convert_to_bytes "${folderSizesArray[@]}")
	totalSize=$(bytesToHuman "${totalSizeInBytes}")
	set +x
	infoboxContent+="**Source Info:**  \n**Total Size:** ${totalSize}"

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
	updateScriptLog "Displaying folder selection dialog."
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
		updateScriptLog "User selected 'Backup'."
		;;
	*) # User selected 'Cancel' or closed the dialog
		updateScriptLog "User selected 'Cancel' or closed the dialog."
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
updateScriptLog "Invoking source and destination selection dialog."
source_destination_dialog

# Validate Selected User and Destination
# --------------------------------------
# Extract the destination path from the selected destination
destination=$(echo "${selectedDestination}" | awk -F'[()]' '{print $(NF-1)}')

# Check if selected user is empty
if [ -z "${selectedUser}" ]; then
	updateScriptLog "No user selected. Exiting."
	clean_quit 1
fi

# Check if selected destination is empty
if [ -z "${selectedDestination}" ]; then
	updateScriptLog "No destination selected. Exiting."
	clean_quit 1
else
	# Get partition name
	parttype=$(diskutil info "${destination}" | grep 'Name (User Visible):' | cut -d ':' -f2 | xargs)
	# Retrieve the mount point of the destination
	get_mount_point "${destination}" # overwrites destination variable
fi

# Disk Speed Test
# ----------------
updateScriptLog "Performing disk speed test at ${destination}/testfile."
dialogUpdate "progresstext: Preforming a speed test on ${destination}"
# Perform a speed test on the drive
mkdir -p "${destination}"
diskSpeed=$(dd if=/dev/zero of="${destination}"/testfile bs=1M count=128 oflag=direct 2>&1 | grep -o '[0-9]\+ bytes/sec' | awk '{print $1}')
# Clean up the test file
rm -f "${destination}"/testfile
# Convert the speed to a human-readable format
diskSpeed="$(bytesToHuman "${diskSpeed}")"
dialogUpdate "progresstext: Disk speed is: ${diskSpeed}/s"
sleep 3
# Add disk speed info to the infobox content
infoboxContent="**Destination Info:**  \n**Speed:** ${diskSpeed}/s  \n**Type**: ${parttype}\n\n"

updateScriptLog "Disk speed test completed: ${diskSpeed}/s."

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
updateScriptLog "Progress dialog initialised."

# Create Destination Directory
# -----------------------------
updateScriptLog "Creating destination directory for user ${selectedUser}."
mkdir -p "${destination}/${selectedUser}"

# Initialise Rsync Failure Flag
# -----------------------------
# Flag to track if rsync fails during execution
rsync_failed=0

# Prepare List of Folders
# ------------------------
# Generate a CSV list of folders to be processed
updateScriptLog "Generating list of folders for processing."
folderListCsv=""
index=0
for folder in "${folders[@]}"; do
	if toBackupFolder; then
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
	updateScriptLog "Drive supports extended attributes, using -avtE"
	rsyncArgs="-avtE"
	;;
Mac\ OS\ Extended\ \(Journaled\))
	updateScriptLog "Drive supports extended attributes, using -avtE"
	rsyncArgs="-avtE"
	;;
*)
	updateScriptLog "Drive does not support extended attributes! using -avt"
	rsyncArgs="-avt"
	;;
esac

# Processing Each Folder
# ----------------------
updateScriptLog "Starting folder processing."
dialogUpdate "progress: 1"

# Create a temporary file for rsync output
rsyncLogFile=$(mktemp -u /var/tmp/rsyncLog.XXX)
touch "${rsyncLogFile}"

for folder in "${folders[@]}"; do
	if toBackupFolder; then
		updateScriptLog "/Users/${selectedUser}/${folder} => ${destination}/${selectedUser}/${folder}"
		dialogUpdate "listitem: index: ${index}, status: progress, statustext: Processing"

		# Initialize an array for rsync exclude options
		rsyncExcludeOpts=()
		for exc in "${excludePatterns[@]}"; do
			if [[ "${exc}" == "${folder}"/* ]]; then
				subfolder="${exc#${folder}/}"
				rsyncExcludeOpts+=(--exclude="${subfolder}")
			fi
		done

		[[ -n "${rsyncExcludeOpts}" ]] && updateScriptLog "${folder}: rsync excludes are: '${rsyncExcludeOpts[*]//--exclude=/./}'"

		# Run rsync in the background, redirecting output to the temp file
		/usr/local/bin/rsync ${rsyncArgs} --no-i-r --delete --info=progress2 --out-format="%f" "${rsyncExcludeOpts[@]}" "/Users/${selectedUser}/${folder}/" "${destination}/${selectedUser}/${folder}" >"${rsyncLogFile}" 2>&1 &
		rsync_pid=$!

		file_name=""
		progress=""
		update_needed=false
		last_update=0
		# Read the latest lines of the log file
		while kill -0 ${rsync_pid} 2>/dev/null; do
			# this, indeed, does use quite the chunk of cpu %
			while IFS= read -r line; do
				# Break the loop if rsync is no longer running
				kill -0 ${rsync_pid} &>/dev/null || break

				# Check if line contains progress info
				if [[ "${line}" =~ ^[[:space:]]+[0-9]+ ]]; then
					progress=$(echo "${line}" | awk '{print $3}' | tr -d '%')
					update_needed=true
				else
					file_name="${line}"
					update_needed=true
				fi

				# Throttle the updates to once per second
				current_time=$(date +%s)
				if [[ "$update_needed" == true ]] && ((current_time > last_update)); then
					if [[ -n "${file_name}" && -n "${progress}" ]]; then
						dialogUpdate "progresstext: ${file_name}"
						dialogUpdate "listitem: index: ${index}, progress: ${progress}"
						update_needed=false
						last_update=$(date +%s)
					fi
				fi
			done < <(tail -n 2 "${rsyncLogFile}")
		done

		# Wait for rsync to finish
		wait ${rsync_pid}

		# Capture the rsync exit status
		rsync_status=$?

		# Update Dialog based on rsync result
		if [ "${rsync_status}" -eq "0" ]; then
			dialogUpdate "listitem: index: ${index}, status: success, statustext: Done!"
		else
			dialogUpdate "listitem: index: ${index}, status: fail, statustext: Failed!"
			rsync_failed="1"
		fi

		# Increment index and update progress
		((index++))
		dialogUpdate "progress: increment ${progressIncrementValue}"
	fi
done

# Remove the temporary file
rm -f "${rsyncLogFile}"

# Final Dialog Update
# -------------------
updateScriptLog "Finalising the process."
if [ "${rsync_failed}" -eq "0" ]; then
	dialogUpdate "progresstext: Completed Successfully!"
	dialogUpdate "icon: sf=externaldrive.fill.badge.checkmark"
	dialogUpdate "progress: complete"
else
	dialogUpdate "progresstext: Some folders failed to backup"
	dialogUpdate "icon: sf=externaldrive.fill.badge.xmark"
	dialogUpdate "progress: reset"
fi

# Enable 'Close' Button
dialogUpdate "button1text: Close"
dialogUpdate "button1: enable"
sleep 1

# Exit Script
updateScriptLog "Script execution completed."
clean_quit 0
