import pandas as pd
import random

data = []

for i in range(1000):

    requests = random.randint(10, 20000)

    protocol = random.choice([
        "TCP",
        "UDP"
    ])

    if requests > 10000:
        attack = 1
    else:
        attack = 0

    data.append([
        requests,
        protocol,
        attack
    ])

df = pd.DataFrame(
    data,
    columns=[
        "Requests",
        "Protocol",
        "Attack"
    ]
)

df.to_csv(
    "ddos_dataset.csv",
    index=False
)

print("Dataset Created Successfully")