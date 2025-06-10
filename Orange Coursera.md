
## Linux
### WGET
##### Download requisites
Download the same page with the necessary images.
```bash
wget <url> --page-reauisites --rejected-log=rejects.log
```
It might print out rejects and missing files, images...etc if the stuff looking for is not form the site itself, but from an external source.
This will mess up with the links to the page, so we need to: 
##### Convert the links
```bash
wget <url> --page-reauisites --rejected-log=rejects.log --span-hosts --convert-links
```

##### Automated
```bash
wget <url> \
	--page-reauisites \
	--rejected-log=rejects.log \
	--convert-links \
	--recursive \ 
	--level=inf \
	--no-parent \ 
	--wait=2 \
	--limit-rate=1024K
```

### RSYNC
Synchronize a replica of the source in the destination. Doesn't remove from destination. Lets a backup of the source + old ones.
##### For all files and directories
```bash
rsync <source-dir>/* <destination-dir> --recursive --verbose --itemize-changes --times
```
##### Create an exact copy of the source
```bash
rsync <source-dir>/ <destination-dir> --recursive --verbose --itemize-changes --times --delete
```

### ABOUT PROCESSES
##### All processes, with all users
```bash
ps -aux | grep <specific process>
pstree 
```
##### Realtime
```bash
top
htop
```

##### Killing
```bash
kill <PID>
kilall <app-name> # Combine with htop
```

```bash
man kill
kill -9 <PID> # More specific
```












