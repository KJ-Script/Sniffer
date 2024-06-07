import numpy as np


def iat_mean(iat_array):
    if len(iat_array) > 0:
        iat = np.diff(iat_array)
        mean = np.mean(iat)
        return mean
    else:
        return 0


def mean(array):
    if len(array) > 0:
        return np.mean(array)
    else:
        return 0


def concatenated_mean(for_array, back_array):
    if len(for_array) > 0 and len(back_array) > 0:
        iat_array = np.concatenate((for_array, back_array))
        mean = np.mean(iat_array)
        return mean
    elif len(for_array) == 0 and len(back_array) == 0:
        return 0
    elif len(for_array) > 0 and len(back_array) == 0:
        return np.mean(for_array)
    elif len(for_array) == 0 and len(back_array) > 0:
        return np.mean(back_array)
    else:
        return 0


def iat_std(for_array, back_array):
    iat_array = np.concatenate((for_array, back_array))
    sorted_array = np.sort(iat_array)
    return std(sorted_array)


def std(array):
    if len(array) > 0:
        return np.std(array)
    else:
        return 0


def sum_of_all(array):
    if len(array) > 0:
        return np.sum(array)
    else:
        return 0


def extreme_diff(array):
    if len(array) > 0:
        largest = max(array)
        smallest = min(array)
        return largest - smallest
    else:
        return 0


def per_sec(length, time):
    length_sum = sum_of_all(length)
    diff = extreme_diff(time)
    if diff > 0:
        return length_sum / diff
    else:
        return 0
