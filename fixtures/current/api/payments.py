"""INTENTIONALLY VULNERABLE FIXTURE. Read and scan only; never run this module."""
import sqlite3
import subprocess
import yaml


def find_payments(customer_id: str):
    connection = sqlite3.connect(":memory:")
    query = f"SELECT * FROM payments WHERE customer_id = '{customer_id}'"
    return connection.execute(query).fetchall()


def reconcile_account(account_id: str):
    command = f"reconcile --account {account_id}"
    return subprocess.check_output(command, shell=True)


def load_payment_policy(document: str):
    return yaml.load(document, Loader=yaml.Loader)
