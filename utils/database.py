import pandas as pd
import json
import os

def Register(DATA, IP, PORT):
    DATA = str(DATA).replace("'", '"')
    DATA = json.loads(DATA)
    df = pd.DataFrame(DATA)
    if os.path.isfile('./utils/main.csv'):
        df.to_csv('./utils/main.csv', mode='a', header=False, index=False)
    else:
        df.to_csv('./utils/main.csv', index=False)
    print("\033[1m\033[92m" + "[LOG]" + "\033[0m", "\033[93m" + f"{IP}:{PORT}" + "\033[0m", "\033[1m" + "-->" + "\033[0m", "\033[93m" + f"{IP}:DB" + "\033[0m", "\033[1m\033[92m" + "[200 OK]" + "\033[0m")
