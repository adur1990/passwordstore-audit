# passwordstore-audit
A simple bash script to check various password security criteria

## What does it
This script checks four criteria for your passwordstore.
1. **Reuse:** Check, if any password is used more than once.
2. **Age:** Check, if any password is older than two months.
3. **Breaches:** Check, if any password was breached using the Have I Been Pwnd
   API.
4. **Weakness:** Check, if any password is weak according to Dropbox' zxcvbn
   algorithm.

## How does it check these things?
For checking if any password is used more than once, it will decrypt all
passwords and check if any is available more than once.  The age check uses the
`pass` extension `pass-ages`. This requires that your passwordstore uses git,
otherwise, it is not possible to get the age of your password.  Finally, the
last two checks (breaches and weakness) are checked using the `pass` extension
`pass-audit`.  This requires Python3 and some `pip` packages.

## Requirements
* [Passwordstore](https://www.passwordstore.org)
* [`pass-ages`](https://github.com/tijn/pass-age)
* [`pass-audit`](https://github.com/roddhjav/pass-audit)

## Usage
```shell
Usage: audit.sh [-h] [-v] [-b] [-w] [-o] [-n]

Script description here.

Available options:

-h, --help      Print this help and exit
-v, --verbose   Print script debug info
-n, --no-color  Disable colored output (e.g., for scripting)
-b, --breached  Check if any password was breached using Have I Been Pwned API
                (Requires "pass audit" extension to be installed)
-w, --weak      Check if any password is weak using Dropbox' zxcvbn algorithm.
                (Requires "pass audit" extension to be installed)
-o, --old       Check if any password is too old.
                (Requires "pass ages" extension to be installed)
-d, --dup       Check if any password is used more than once.
```