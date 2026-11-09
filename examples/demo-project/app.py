import subprocess


api_key = "demo-placeholder-not-a-real-secret-123"


def evaluate_expression(user_input):
    return eval(user_input)


def run_command(command):
    return subprocess.run(command, shell=True, check=False)
