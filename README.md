# rosa-python-client
Pypi: [rosa-python-client](https://pypi.org/project/rosa-python-client/)  
A utility to run ROSA commands in CLI

## Release new version
### requirements:
* Export GitHub token

```bash
export GITHUB_TOKEN=<your_github_token>
```
* [release-it](https://github.com/release-it/release-it)

```bash
sudo npm install --global release-it
npm install --save-dev @release-it/bumper
```
### usage:
* To create a new release, run:

```bash
git main
git pull
release-it # Follow the instructions
```
