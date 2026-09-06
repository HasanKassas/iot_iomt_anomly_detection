import pandas as pd

def load_data(path):
    data = pd.read_csv(path)
    return data