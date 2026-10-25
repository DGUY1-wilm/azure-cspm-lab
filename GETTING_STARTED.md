# Getting Started: Run This Lab Yourself

<!-- [AI-generated draft] Claude, 2026-10-25. Reviewed and edited by Daniel: [ ] pending -->

This guide walks you through the whole lab in plain language: you'll set up a small piece of
cloud infrastructure, make it insecure on purpose, catch the problems with a free scanning tool,
rank them by how dangerous they really are, fix them, and clean everything up. You don't need to
be a programmer. You'll copy and paste commands, and each step explains what the command does,
why it matters, and what you should see.

**Time:** about 4–6 hours, spread over a day or two.
**Cost:** $0 if you follow the guide (see the safety rules below).
**Computer:** Windows 11. (Mac and Linux work too, but the commands here are written for Windows.)

---

## Words you'll see

| Word | Plain meaning |
|---|---|
| **Cloud / Azure** | Renting computers and storage from Microsoft over the internet. Azure is Microsoft's cloud. |
| **Subscription** | Your Azure account's billing container. Everything you create lives inside it. |
| **Resource group** | A folder inside your subscription. This lab keeps everything in one folder so cleanup is one click. |
| **Misconfiguration** | A setting that's wrong, like leaving a door unlocked. Most cloud breaches start this way. |
| **Scanner** | A program that checks your settings against a list of security rules and reports what fails. |
| **CSPM** | Cloud Security Posture Management: the job of finding and fixing cloud misconfigurations. |
| **Prowler** | The free, open-source scanner this lab uses. |
| **Finding** | One result from the scanner: "this check, on this thing, passed or failed." |
| **Terminal / PowerShell** | The window where you type commands. Search "PowerShell" in the Start menu. |

---

## Safety rules (read before anything else)

1. **Only scan what you own.** Every command in this guide is limited to your own subscription and
   your own resource group. Never point these tools at anyone else's account, even if you can.
2. **Never spend money.** Use a credit-based account (like Azure for Students), set a budget alert
   first, and never create virtual machines or anything billed by the hour. If a step could cost
   money, this guide says so.
3. **Never share your IDs or secrets.** Scan results contain your subscription ID and other
   identifiers. The project is set up so those files never go into Git or onto GitHub. Blur IDs in
   any screenshot you share.
4. **Clean up at the end.** The last step deletes everything you created.

---

## Part 1: Get your computer ready

You'll install four free tools. If a tool is already installed, skip it.

**Open PowerShell as a normal user** (not "Run as administrator") for everything except step 1.3.

### 1.1 Install Git (for downloading the project)

```powershell
winget install --exact --id Git.Git
```

### 1.2 Install Python 3.12

Use **3.12** specifically. Newer versions can be too new for the tools in this lab (we hit this:
Python 3.15 couldn't install a required package).

```powershell
winget install --exact --id Python.Python.3.12
```

### 1.3 Allow long file paths (one-time Windows setting)

Prowler includes some files with very long names, and Windows blocks long paths by default.
This one-time change needs an **administrator** PowerShell window: right-click PowerShell and
choose "Run as administrator", run this line, then close that window.

```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```

### 1.4 Install the Azure command-line tool

```powershell
winget install --exact --id Microsoft.AzureCLI
```

### 1.5 Install Prowler (the scanner)

**Close and reopen PowerShell first** so it finds the tools you just installed. Then:

```powershell
py -3.12 -m pip install --user pipx
py -3.12 -m pipx ensurepath
```

Close and reopen PowerShell again, then:

```powershell
py -3.12 -m pipx install prowler
prowler -v
```

✅ **You should see** a version number like `Prowler 5.45.0`. The install can take several
minutes; a quiet screen is normal.

### 1.6 Download the project

Pick a folder you'll remember, then:

```powershell
cd $HOME\Documents
git clone https://github.com/DGUY1-wilm/azure-cspm-lab.git
cd azure-cspm-lab
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

✅ **You should see** `(.venv)` at the start of your PowerShell line. That means the project's
own Python environment is active. **Every time you open a new PowerShell window for this lab**,
run `cd` into the project folder and `.venv\Scripts\Activate.ps1` again.

If `Activate.ps1` is blocked, run this once and try again:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

---

## Part 2: Set up Azure safely

### 2.1 Sign in

```powershell
az login
```

A browser window opens. Sign in with the account that owns your Azure subscription.

### 2.2 Check what you're allowed to scan

```powershell
az account list --query "[].{name:name, state:state}" -o table
az account show --query "{subscription:name, tenantDomain:tenantDefaultDomain}" -o table
```

- The first command lists every subscription your login can see. **You should only scan the one
  you created for this lab.**
- The second shows which organization's directory your subscription belongs to. If it's a school
  or employer domain, that directory isn't yours, so this lab skips directory-wide checks
  (that's already built into the scan script).

These commands only show names, not ID numbers, on purpose.

### 2.3 Set a budget alert

In the [Azure portal](https://portal.azure.com): search **Cost Management** → **Budgets** →
**Add**. Use these settings:

- Scope: your subscription · Name: `cspm-lab-budget` · Amount: **$5** per month
- Alerts: **Actual** at 50% and 100%, **Forecasted** at 80%, sent to your email

A budget only **warns** you; it doesn't stop spending. On a student or credit account, the credit
running out is the real stop. The $5 alert just tells you early if something's wrong.

### 2.4 Make sure paid security plans are off

Portal: **Microsoft Defender for Cloud** → **Environment settings** → your subscription →
**Defender plans**. Everything except "Foundational CSPM" should be **Off**.

### 2.5 Find which regions you're allowed to use

Some subscriptions (Azure for Students, for example) can only create things in certain regions.
Portal: search **Policy** → **Assignments** → open **Allowed resource deployment regions** →
**View assignment** → look at **Allowed locations**.

Pick one region from that list and remember its short name (like `westus2`). If you don't see that
policy, any US region like `eastus` works.

### 2.6 Create the lab's resource group

Replace `westus2` with your region if it's different:

```powershell
$rg = "rg-cspm-lab"
$region = "westus2"
az group create --name $rg --location $region --tags project=cspm-lab
```

> 💡 **If you close PowerShell**, these `$rg` and `$region` values are forgotten. Re-run the first
> two lines before any later step that uses them.

---

## Part 3: Take a "before" picture

Run the first scan before creating anything, so you can see your account's starting point.

```powershell
.\scripts\run_scan.ps1 -Label baseline
```

This one command runs the scanner, saves the results, checks your network rules, ranks the
findings, and builds a report. The scan itself takes about a minute.

If PowerShell says the script is blocked, run this once, then try again:
`Get-ChildItem scripts, infra -Filter *.ps1 | Unblock-File`

✅ **You should see** a list of findings marked P3 or "excluded". Even an empty account fails some
checks, mostly about missing alerts and logging. That's normal.

Open the report:

```powershell
Invoke-Item reports\report.html
```

### How to read the priority labels

| Label | Meaning | Example |
|---|---|---|
| **P1** | Exposed right now: anyone on the internet can reach it | A file anyone can download |
| **P2** | Makes exposure possible or easier | A storage account reachable from any network |
| **P3** | You wouldn't notice an attack | No alert when firewall rules change |
| **P4** | Extra hardening; nice to have | Using your own encryption keys |
| **Excluded** | Deliberately set aside, with a written reason | A paid feature, or something you don't own |

These labels come from this project's own rules, not the scanner's. The scanner rates many
harmless things "high"; this lab's job is to tell you which ones actually matter.

---

## Part 4: Leave a file open to the internet

**What you're doing:** creating cloud storage and making one harmless text file readable by
anyone, the most common real-world cloud leak.

⚠️ **Cost:** a fraction of a cent. Storage is billed per gigabyte, and your file is a few bytes.

```powershell
$sa = "cspmlab$(Get-Random -Minimum 10000 -Maximum 99999)"
az storage account create --name $sa --resource-group $rg --location $region --sku Standard_LRS --kind StorageV2 --min-tls-version TLS1_2 --allow-blob-public-access true --tags project=cspm-lab
az storage container create --name public-demo --account-name $sa --public-access blob --auth-mode key
$testFile = Join-Path $env:TEMP "test.txt"
"Harmless test file for a CSPM lab. No real data." | Out-File -Encoding utf8 $testFile
az storage blob upload --account-name $sa --container-name public-demo --name test.txt --file $testFile --auth-mode key
```

The storage name gets random numbers because every storage name in Azure must be unique worldwide.
**Never put real data in this container.**

### Prove it's exposed, like an attacker would

These two lines ask for the file with **no password at all**:

```powershell
Invoke-RestMethod "https://$sa.blob.core.windows.net/public-demo/test.txt"
Invoke-RestMethod "https://$sa.blob.core.windows.net/public-demo?restype=container&comp=list"
```

✅ **You should see** your test sentence from the first line (anyone can read it), and an error
from the second (nobody can list what else is there). A few odd characters like `ï»¿` before the
sentence are a harmless Windows text-file marker.

### Scan it

```powershell
.\scripts\run_scan.ps1 -Label after-public-blob -Before baseline
```

✅ **You should see** one **P1** finding: `storage_blob_public_access_level_is_disabled`, plus
several lower-priority storage findings. A brand-new storage account fails many checks with its
default settings; only one of them is real exposure.

### Fix it and check again

```powershell
az storage container set-permission --name public-demo --account-name $sa --public-access off --auth-mode key
az storage account update --name $sa --resource-group $rg --allow-blob-public-access false
Invoke-RestMethod "https://$sa.blob.core.windows.net/public-demo/test.txt"
```

✅ The last line should now **fail**. (Wait a minute and retry if it still works.) Then:

```powershell
.\scripts\run_scan.ps1 -Label after-remediation -Before after-public-blob
```

✅ **You should see** `fixed P1 storage_blob_public_access_level_is_disabled`.

---

## Part 5: Open the remote-login doors to the internet

**What you're doing:** creating a firewall rule (Azure calls it a **Network Security Group**, or
NSG) that lets anyone on the internet try to log in remotely: port 22 (SSH, used by Linux) and
port 3389 (RDP, used by Windows). These are the most attacked doors on the internet.

⚠️ **Cost:** free. The firewall isn't attached to any computer, so nothing is actually exposed.
It's a loaded trap: harmless until someone attaches it to a machine.

```powershell
az network nsg create --name nsg-cspm-open --resource-group $rg --location $region --tags project=cspm-lab
az network nsg rule create --nsg-name nsg-cspm-open --resource-group $rg --name allow-ssh-rdp-from-any --priority 100 --direction Inbound --access Allow --protocol Tcp --source-address-prefixes "*" --source-port-ranges "*" --destination-address-prefixes "*" --destination-port-ranges 22 3389
.\scripts\run_scan.ps1 -Label after-open-nsg -Before after-remediation
```

✅ **What to notice:** the project's own check (marked `custom_nsg_…`) reports both SSH and RDP as
open. **Prowler's own checks pass this rule.** That's a real gap in Prowler: when one rule lists
more than one port, its SSH and RDP checks don't see them. The full investigation is in
[docs/findings/prowler-nsg-multiport-false-negative.md](docs/findings/prowler-nsg-multiport-false-negative.md).
The lesson: **don't assume a security tool catches everything; test it.**

### Fix it

```powershell
az network nsg rule delete --nsg-name nsg-cspm-open --resource-group $rg --name allow-ssh-rdp-from-any
```

(You'll scan once more after Part 6, which covers this fix too.)

---

## Part 6: Give an unused account far too much power

**What you're doing:** creating a "managed identity" (a robot account that programs can use) and
giving it **User Access Administrator**, a role that can grant anyone any permission. Accounts
with powerful access that nobody uses or watches are a classic way attackers move up.

⚠️ **Cost:** free.

```powershell
$subscription = az account show --query id -o tsv
az identity create --name id-cspm-unused --resource-group $rg --location $region --tags project=cspm-lab
$principalId = az identity show --name id-cspm-unused --resource-group $rg --query principalId -o tsv
az role assignment create --assignee-object-id $principalId --assignee-principal-type ServicePrincipal --role "User Access Administrator" --scope "/subscriptions/$subscription"
.\scripts\run_scan.ps1 -Label after-identity -Before after-open-nsg
```

If the last `az` command says the principal wasn't found, wait a minute and run it again. New
accounts take a moment to appear everywhere.

✅ **You should see** a new **P2** finding: `iam_role_user_access_admin_restricted`.

### Fix it: remove the access, keep the account for now

Always **remove an account's access before deleting the account**. Deleting the account first
leaves "ghost" permissions behind that are hard to track down.

```powershell
$assignmentId = az role assignment list --scope "/subscriptions/$subscription" --role "User Access Administrator" --fill-principal-name false --query "[?principalId=='$principalId'].id" -o tsv
$assignmentId.Count
```

✅ That should print **1**. If it prints anything else, stop and investigate before deleting.

```powershell
az role assignment delete --ids $assignmentId
.\scripts\run_scan.ps1 -Label after-fixes -Before after-identity
```

✅ **You should see** the firewall findings as **fixed** and the access finding as **gone**
(the permission was deleted, which is the fix for this kind of finding).

---

## Part 7: Turn on an alarm and test it

**What you're doing:** fixing one P3 finding by setting up email alerts whenever someone creates,
changes, or deletes a firewall rule, the exact change you made in Part 5.

⚠️ **Cost:** free. Activity log alerts are free, and the first 1,000 emails per month are free.

Replace the email address with yours:

```powershell
$scope = "/subscriptions/$subscription"
az monitor action-group create --name ag-cspm-lab --resource-group $rg --short-name cspmlab --action email me you@example.com
$agId = az monitor action-group show --name ag-cspm-lab --resource-group $rg --query id -o tsv
az monitor activity-log alert create --name alert-nsg-write --resource-group $rg --scope $scope --condition "category=Administrative and operationName=Microsoft.Network/networkSecurityGroups/write" --action-group $agId
az monitor activity-log alert create --name alert-nsg-delete --resource-group $rg --scope $scope --condition "category=Administrative and operationName=Microsoft.Network/networkSecurityGroups/delete" --action-group $agId
```

You'll get a "You've been added to an action group" email. That's a confirmation, not an alert.

### Test the alarm

Create a throwaway firewall and delete it right away. That should set off **both** alarms:

```powershell
az network nsg create --name nsg-alert-test --resource-group $rg --location $region --tags project=cspm-lab
az network nsg delete --name nsg-alert-test --resource-group $rg
```

✅ Within a few minutes, you should get **two alert emails**. Check your spam folder. These alerts
aren't instant; note how long they took.

```powershell
.\scripts\run_scan.ps1 -Label after-alerts -Before after-fixes
```

✅ **You should see** two P3 findings marked **fixed**.

---

## Part 8: Clean up everything

```powershell
.\infra\teardown.ps1
```

The script lists everything it will delete and asks you to **type the resource group name** to
confirm. It removes leftover permissions first, then deletes the whole folder, then checks it's gone.

Then take the final "after" picture:

```powershell
.\scripts\run_scan.ps1 -Label after-teardown -Before after-alerts
```

✅ **What to notice:** your storage findings are **gone** (deleted, not fixed), and the two alert
findings come back as **new**. The alarms lived inside the lab folder, so cleaning up deleted them
too. In a real company, that's how a routine cleanup quietly switches off security alerts, which is
why monitoring should live in its own separate folder.

**The next day**, check Cost Management in the portal to confirm your spend. Cost data can take up
to a day to appear.

---

## If something goes wrong

| What you see | What it means | What to do |
|---|---|---|
| `AADSTS50173` or "grant has expired… revoked" | Your Azure sign-in was ended (common with school accounts) | `az logout`, then `az login`, then retry |
| `RequestDisallowedByAzure` … "best available regions" | That region isn't allowed for your subscription | Use a region from Part 2.5 |
| `prowler` "is not recognized" | PowerShell can't find Prowler yet | Close and reopen PowerShell; re-run `py -3.12 -m pipx ensurepath` |
| Error mentioning "Microsoft Visual C++" | You're on a Python version that's too new | Use Python 3.12 (Part 1.2) |
| "No such file or directory" with a very long path during install | Windows long-path limit | Do Part 1.3, reopen PowerShell, reinstall |
| Prompt starts with `C:\WINDOWS\system32` | You're in an administrator window | Open a normal PowerShell and `cd` into the project |
| "No scan with label…" or "already exists" | A scan name was mistyped or reused | Use the exact label names from this guide; each must be new |
| "is empty; did the 'az network nsg list' command fail?" | An Azure command failed earlier (usually an expired sign-in) | `az login`, then re-run the scan with a **new** label |
| `$sa`, `$rg`, or `$subscription` is empty | You opened a new PowerShell window | Re-run the lines that set them (Parts 2.6, 4, and 6) |

---

## What you've learned

- How cloud resources become exposed through **settings**, not software bugs
- How to prove exposure the way an attacker would, instead of trusting a settings page
- Why a scanner's "high/medium/low" labels aren't the same as real risk
- How to test your security tools, and what to do when they miss something
- Why cleanup needs to be checked too: removing things can also remove protections
