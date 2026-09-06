from src.evaluate_comparison import evaluate_all, _prepare_xy
from src.load_data import load_data


def main():
    df = load_data("data/train_test_network.csv")
    X_df, y = _prepare_xy(df)
    evaluate_all(X_df, y)


if __name__ == "__main__":
    main()
