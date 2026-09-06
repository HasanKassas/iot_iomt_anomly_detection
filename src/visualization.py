import pandas as pd
import matplotlib.pyplot as plt
import os

def plot_feature_importance(model, feature_names):
    importance = pd.Series(
        model.feature_importances_,
        index=feature_names
    ).sort_values(ascending=False)

    plt.figure()
    importance.head(15).plot(kind='barh')
    plt.title("Top 15 Feature Importance")
    plt.gca().invert_yaxis()

    os.makedirs("results", exist_ok=True)
    plt.savefig("results/feature_importance_rf.png")

    plt.show()
