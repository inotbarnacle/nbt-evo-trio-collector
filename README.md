# NBT Evo Trio Collector

Get the Mac or Windows x64 download from the [Collector releases](https://github.com/inotbarnacle/nbt-evo-trio-collector/releases).

The collector reads firmware and framework information over SSH. It helps identify what BoostDeck, ShiftDeck and MHD Maps need for another firmware version.

1. Extract the macOS or Windows x64 ZIP and open the app. It opens a tab in your default browser. The Mac app is ad-hoc signed and the Windows EXE is unsigned.
2. Park the car, connect an OBD ENET cable and enable temporary SSH for your firmware. [Bavarian SSH Client](https://ssh.bavarian-aa.uk/).
3. Click **Find car** to look up the gateway and head unit addresses. If only the gateway appears, enter the head unit SSH address reported by your unlock tool. **Try defaults** checks the reference car's head unit at `169.254.199.119`. Its gateway is `169.254.21.3`. Other cars may use different addresses.
4. Click **Collect and review**. Verify the displayed SSH fingerprint against your known connection, then confirm it to collect. The collector uses the built-in default root password. It requires a unit configured with that password. If firmware detection needs help, enter the complete `NBTevo_…` code shown in iDrive.
5. Review the ZIP contents and click **Download ZIP**. Attach the downloaded ZIP in your usual email app and send it to **nordicbmwdealer@gmail.com**.

The default ZIP contains `compatibility.json`, including the firmware code, HMI build when available, and hashes, sizes and exported symbol names for two framework libraries. The optional library checkbox adds the two library files themselves. Select it only if you have permission to share them.

## Find the addresses from a terminal

Run these commands from the folder where you extracted the download, with the car connected over ENET.

On macOS, use Terminal:

```sh
"./NBT Evo Trio Collector.app/Contents/MacOS/NBTEvoTrioCollector" --find-car
```

On Windows, use Command Prompt:

```cmd
start "" /wait "NBT Evo Trio Collector.exe" --find-car --output "%TEMP%\trio-enet.txt"
type "%TEMP%\trio-enet.txt"
```

The output labels **Gateway IP**, **Head unit SSH IP** and **Computer ENET IP**. Use the gateway IP when the unlock tool asks for it. Use the head unit SSH IP in the Collector. If the output says the head unit IP is unavailable, use the head unit address shown in the unlock tool. If the gateway appears but SSH times out, check that iDrive is awake and temporary SSH is enabled.

To build from source on macOS, run `./build-release.sh` with Go and the Apple command line developer tools installed.
