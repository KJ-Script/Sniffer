from features.flags.flag_deconstruction import deconstruct


def flags(packet):
    return deconstruct(packet)


def flag_count(array, flag):
    count = 0
    for flag_array in array:
        for item in flag_array:
            if item is not None:
                if item == flag:
                    count += 1
    return count
