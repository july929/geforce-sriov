# Compatibility reports

Submit a [compatibility report](https://github.com/noon-at-cgn/geforce-sriov/issues/new?template=compatibility-report.yml) to record whether geforce-sriov works on your card and host.
Reports from other machines help establish which cards and hosts work.
Failed and partially working setups are just as useful: choose *Does not work* or *Partially* in the form and say where it stopped.

See [Supported cards](devices.md#status-of-every-row) for the status of every card and driver version.
See the [Ampere](ampere.md) and [Ada](ada.md) pages for generation-specific details.
See [Community reports](community-reports.md) for the setups people have reported so far.

Reports are voluntary.
The form takes a few minutes, because one command collects the details.

## Make the report

Run this command on the host:

```
sudo geforce-sriov report
```

In a source checkout without an install, use `sudo ./geforce-sriov report` instead.
The command prints one block that starts with a `~~~text` line and ends with a `~~~` line.
Copy everything from the first of these lines to the last.
To write the block to a file instead, run `sudo geforce-sriov report --out report.txt`.

Run the command with `sudo`.
Without root, the kernel log and some checks are missing from the block.
The command changes nothing on the host.

The `State:` line near the top of the block says whether geforce-sriov is installed and whether the VFs are active.
It also says how many running VMs use a VF now.
The most useful report comes after the power cycle and a first VM that ran with a vGPU.
A report taken right after the install says `State: installed, not yet activated`.
Keep that one for later and make a new report once a VM has run.
`setup` offers to create the report when it ends, and writes it to `/root/geforce-sriov-report.txt` if you say yes.

## What the report holds

| Section | Contents |
|---|---|
| Host | geforce-sriov version, host OS, kernel, hypervisor, CPU, board and firmware, kernel command line, IOMMU state |
| GPUs | For every NVIDIA GPU: PCI ID, subsystem ID, model, generation, VRAM, boot display, driver, SR-IOV and ARI state, BAR placement and the PCIe path with its link speed. The block also tells whether Above 4G decoding is on. |
| Software and settings | NVIDIA host driver version, whether the patched `nvidia.ko` is in use, settings you changed from the defaults and the VF count |
| `status` | The whole output of `geforce-sriov status` |
| Host checks | The whole output of `geforce-sriov install --dry-run` |
| Kernel log | The `geforce_sriov`, `NVRM` and `AER` lines of the current boot, at most 120 lines |

A field is left out when the host lacks the tool that reads it, and the block says so.
The command reads `/sys` and `/proc` and runs `lspci`, `journalctl` (or `dmesg`), `nvidia-smi`, `pveversion`, `virsh` and `qemu-system-x86_64` when they are installed.

The report cannot see inside your guests.
The form asks for those details in one line.
Note for each guest:

- the guest OS
- its vGPU type, the profile set on its VF, such as `RTXA6000-4Q`
- the version of the NVIDIA vGPU guest driver installed in it

For a problem from an earlier boot, run `sudo journalctl -k -b -1 --no-hostname | grep -E 'geforce_sriov|NVRM|AER'` and add the lines to the notes.
This requires a persistent journal.
See [Logs](recovery.md#logs) for other log sources.

## What the report removes

Issues are public.
The command removes these details before it prints:

- IP and MAC addresses
- serial numbers
- GPU UUIDs (`GPU-…`)
- the host name and the user names of the machine
- licence details: lines with licence server addresses or client configuration tokens

The first lines of the block say what was removed and how many times.
Read the block before you post it.
Do not add secrets such as passwords, keys or licence files.

PCI addresses such as `0000:01:00.0`, PCI IDs and version numbers are not private.
The report keeps them.

## Open the report

1. Run `sudo geforce-sriov report` and copy the block.
2. Open the [compatibility report form](https://github.com/noon-at-cgn/geforce-sriov/issues/new?template=compatibility-report.yml), or choose **Issues → New issue → Compatibility report** on GitHub.
3. Choose the result, paste the block into the report field and add your guests and notes.

File one report per card model and host.
If you need a fix for a broken setup, also check [Symptoms](recovery.md#symptoms).

Use a **Bug report** for problems in geforce-sriov's tools or documentation that do not depend on hardware, such as an incorrect message or documentation error.

## What happens to a report

- Reports remain public issues with the `compatibility` label so readers with the same card can find them.
- `geforce-sriov devices` lists every card in the device table, and every listed card is supported. See [Devices](devices.md#generations).
  Maintainers decide whether a report warrants changes to the device table or documentation.
- Reports of failed setups are retained.
  Maintainers decide whether to document them.
- Support, fixes and response times are not guaranteed.
