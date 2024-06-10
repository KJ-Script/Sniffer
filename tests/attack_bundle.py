import ack_flood_attack, fin_flood_attack, icmp_flood_attack, syn_flood_attack, r


def run_attack_bundle():
    syn_flood_attack()
    ack_flood_attack()
    fin_flood_attack()

