import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "app/src/main/java/com/msnguard/vpn/MainActivity.kt").read_text()


class RailOrderContract(unittest.TestCase):
    """3.4.24: MASQUE leads the transport rail, WireGuard second (user request).

    The order lives in ONE place — the Protocol enum — because both the
    home-screen rail and the Connection mode page are built from
    `Protocol.entries`. This pins:

    - MASQUE is declared before WIREGUARD in the enum (so it takes the first
      cell in both surfaces);
    - the swap is a pure reorder: the wireNames, labels, descriptions and
      the rest of the enum are untouched, and every other transport keeps
      its relative position (WoW third, Lantern fourth, ...);
    - the persisted protocol pref stores the core NAME, not an index — so
      an existing user's saved selection survives the swap (savedProtocol
      resolves by coreName with the WIREGUARD fallback intact);
    - the slot cards bind to the SELECTED protocol, never to a rail index:
      the MiM card under MASQUE, the WireGuard-over-Masque card under
      WireGuard — both keyed on selectedProtocol, which the swap cannot
      break."""

    def _enum_block(self) -> str:
        start = MAIN.find("private enum class Protocol(")
        self.assertGreater(start, 0, "Protocol enum not found")
        end = MAIN.find("val label: String get()", start)
        self.assertGreater(end, 0)
        return MAIN[start:end]

    def test_masque_is_declared_before_wireguard(self):
        block = self._enum_block()
        mq = block.find('MASQUE("MASQUE"')
        wg = block.find('WIREGUARD("WireGuard"')
        self.assertGreater(mq, 0, "MASQUE declaration missing")
        self.assertGreater(wg, 0, "WIREGUARD declaration missing")
        self.assertLess(mq, wg, "MASQUE must be declared first — it is the first rail cell")

    def test_the_reorder_is_pure_no_other_declaration_moved(self):
        block = self._enum_block()
        order = [
            ("MASQUE", 'MASQUE("MASQUE"'),
            ("WIREGUARD", 'WIREGUARD("WireGuard"'),
            ("WoW", 'WARP_IN_WARP("WARP-on-WARP"'),
            ("Lantern", 'LANTERN("Lantern"'),
            ("Psiphon", 'PSIPHON("Psiphon"'),
            ("Tor", 'TOR("Tor"'),
            ("Foxy", 'FOXY("Foxy"'),
            ("SHARD", 'SHARD("SHARD"'),
        ]
        positions = [block.find(p) for _, p in order]
        for (name, _), pos in zip(order, positions):
            self.assertGreater(pos, 0, f"{name} declaration missing")
        self.assertEqual(positions, sorted(positions),
                         "the eight transports must appear in exactly this order")

    def test_persisted_selection_is_by_name_not_index(self):
        self.assertIn(
            'preferences().getString(DEFAULT_PROTOCOL, Protocol.WIREGUARD.coreName)',
            MAIN)
        self.assertIn(
            'preferences().edit().putString(DEFAULT_PROTOCOL, protocol.coreName).apply()',
            MAIN)
        self.assertIn(
            "Protocol.entries.firstOrNull { it.coreName == name && it.androidAvailable }",
            MAIN)

    def test_slot_cards_bind_to_the_selected_protocol_not_a_position(self):
        self.assertIn("val masqueSelected = selectedProtocol == Protocol.MASQUE", MAIN)
        self.assertIn("val wireguardSelected = selectedProtocol == Protocol.WIREGUARD", MAIN)
        self.assertIn("mimCard.visibility = if (masqueSelected) View.VISIBLE else View.GONE", MAIN)
        self.assertIn("wgOverMasqueCard.visibility = if (wireguardSelected) View.VISIBLE else View.GONE", MAIN)

    def test_rail_and_mode_page_are_built_from_entries(self):
        # if a surface ever hardcodes an order, this swap silently stops
        # applying to it — so both consumers must stay entries-driven
        self.assertIn("Protocol.entries.map { railLabel(it) }", MAIN)
        self.assertIn("Protocol.entries[index]", MAIN)
        self.assertIn("Protocol.entries.forEachIndexed { index, protocol ->", MAIN)


if __name__ == "__main__":
    unittest.main()
