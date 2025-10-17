# DisableSteamGameUpdate
A python script that prevents steam from updating specific games of your choice

## How does it work?

The script allows you to flag specific games in your library in a way that steam won't be able to update them, and once a new update gets released, you can simply re-run the program to make steam believe the game is already up-to-date, without actually updating the game.

The main purpose for this is for Game installations with heavy Mods that would otherwise break once an update is released.

## Usage

Download the block_game_update.py and place it in an empty folder somewhere on your pc

Download [SteamCMD](https://developer.valvesoftware.com/wiki/SteamCMD) and place the exe in the same folder.

open cmd.exe, navigate to that folder and launch steamcmd one to initialize it.

then run 

> python .\block_game_update --list 

to find a list of installed game appids

look for the game you want to block updates for, and run

> python .\block_game_update --enable (appid)

Now the script will make a backup copy for your manifest and set the manifest read-only to prevent steam from successfully updating the game. It will still show updates when they arrive, but the updates will fail.

Once an update arrives, run

> python .\block_game_update --auto

This will automatically fix the manifest files to the newest versions for all games that you have enabled blocking for.

**Warning: The Auto command, as well as the regular command via --appid will kill steam.exe if it is running, to avoid steam from changing the manifest once the readonly flag is removed. If you want to avoid corrupting downloads, either close steam or make sure no downloads or games are running when you run this command.**

If you wish to update the game again, run

> python .\block_game_update --disable (appid)

That's it. Have fun modding in peace.
