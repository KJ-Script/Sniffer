import numpy as np


def iat_mean(iat_array):
    iat = np.diff(iat_array)
    mean = np.mean(iat)
    return mean


def mean(array):
    return np.mean(array)


def concatenated_mean(for_array, back_array):
    iat_array = np.concatenate((for_array, back_array))
    mean = np.mean(iat_array)
    return mean


def iat_std(for_array, back_array):
    iat_array = np.concatenate((for_array, back_array))
    sorted_array = np.sort(iat_array)
    return std(sorted_array)


def std(array):
    return np.std(array)


def sum_of_all(array):
    return np.sum(array)


def extreme_diff(array):
    largest = max(array)
    smallest = min(array)
    return largest - smallest


def per_sec(length, time):
    length_sum = sum_of_all(length)
    diff = extreme_diff(time)
    return length_sum / diff
