# Copyright(C) Facebook, Inc. and its affiliates.
from json import load, JSONDecodeError


class SettingsError(Exception):
    pass


class Settings:
    def __init__(self, testbed, key_name, key_path, base_port, repo_name, repo_url,
                 branch, deploy_key, instance_type, aws_regions):
        inputs_str = [
            testbed,
            key_name,
            key_path,
            repo_name,
            repo_url,
            branch,
            deploy_key,
            instance_type
        ]
        if isinstance(aws_regions, list):
            regions = aws_regions
        else:
            regions = [aws_regions]
        inputs_str += regions
        ok = all(isinstance(x, str) for x in inputs_str)
        ok &= isinstance(base_port, int)
        ok &= len(regions) > 0
        if not ok:
            raise SettingsError('Invalid settings types')

        self.testbed = testbed

        self.key_name = key_name
        self.key_path = key_path

        self.base_port = base_port

        self.repo_name = repo_name
        self.repo_url = repo_url
        self.branch = branch
        self.deploy_key = deploy_key

        self.instance_type = instance_type
        self.aws_regions = regions

    @classmethod
    def load(cls, filename):
        try:
            with open(filename, 'r') as f:
                data = load(f)

            return cls(
                data['testbed'],
                data['key']['name'],
                data['key']['path'],
                data['port'],
                data['repo']['name'],
                data['repo']['url'],
                data['repo']['branch'],
                data['repo']['deploy_key'],
                data['instances']['type'],
                data['instances']['regions'],
            )
        except (OSError, JSONDecodeError) as e:
            raise SettingsError(str(e))

        except KeyError as e:
            raise SettingsError(f'Malformed settings: missing key {e}')
