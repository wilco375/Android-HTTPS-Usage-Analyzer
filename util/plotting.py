import numpy as np
from matplotlib import pyplot as plt
from util.text import uc_first


def add_bar_chart_labels(bar_count, values):
    """
    Add labels with the value of each bar to a bar chart
    :param bar_count: number of bars
    :type bar_count: int
    :param values: bar values
    :type values: list[int]
    """
    for i in range(bar_count):
        plt.text(i, values[i] + max(values) * 0.01, values[i], ha='center')


def plot_bar_chart(labels, values, y_label, title, rotate_labels=False):
    """
    Plot a bar chart using matplotlib with the given labels and values
    :param labels: bar labels
    :type labels: list[str]
    :param values: bar values
    :type values: list[int]
    :param y_label: label of y-axis
    :type y_label: str
    :param title: title of the chart
    :type title: str
    :param rotate_labels: rotate the labels by 10 degrees to make long labels readable
    :type rotate_labels: bool
    """
    y_pos = np.arange(len(labels))
    fig = plt.figure(figsize=(len(labels)*2, 6))
    plt.bar(y_pos, values, align='center')
    add_bar_chart_labels(len(labels), values)
    if rotate_labels:
        plt.xticks(y_pos, map(uc_first, labels), rotation=-10, ha='left')
    else:
        plt.xticks(y_pos, map(uc_first, labels))
    plt.ylabel(y_label)
    plt.title(title)
    fig.tight_layout()
    plt.show()
