#   Description:
# This scripts places the "God Mode" folder on the current user's desktop.

Write-Information @"
###############################################################################
#       _______  _______  ______     __   __  _______  ______   _______       #
#      |       ||       ||      |   |  |_|  ||       ||      | |       |      #
#      |    ___||   _   ||  _    |  |       ||   _   ||  _    ||    ___|      #
#      |   | __ |  | |  || | |   |  |       ||  | |  || | |   ||   |___       #
#      |   ||  ||  |_|  || |_|   |  |       ||  |_|  || |_|   ||    ___|      #
#      |   |_| ||       ||       |  | ||_|| ||       ||       ||   |___       #
#      |_______||_______||______|   |_|   |_||_______||______| |_______|      #
#                                                                             #
#      God Mode has been enabled, check out the new link on your Desktop      #
#                                                                             #
###############################################################################
"@ -InformationAction Continue

New-Item -Path ([Environment]::GetFolderPath("Desktop")) -Name "GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" -ItemType Directory -ErrorAction SilentlyContinue