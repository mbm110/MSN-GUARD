"""Guard the WireGuard Over MASQUE carrier choice (3.2.45).

Same shape as the WoW gool carrier (see test_gool_over_masque_contract.py):
armed, a WireGuard connect runs wireguard INSIDE the masque tunnel with the
identity registered THROUGH it, on the exact engine path the armed WoW card
takes. Off by default: plain wireguard is the state every WireGuard build
shipped with; the masque carrier is opt-in and remembered.

The single switch that makes this work: CoreConfig maps an armed
"wireguard" selection to protocol "gool" — the service keys its whole setup
(SOCKS-front prep, MTU method, udpgw, lastconn) and the engine its arm
(Protocol::WarpInWarp if !gool_classic()) off that field, so the armed run
is the proven WoW-over-MASQUE one, not a new transport.
"""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "app/src/main/java/com/msnguard/vpn"
CORE = (APP / "CoreConfig.kt").read_text()
UI = (APP / "MainActivity.kt").read_text()
SERVICE = (APP / "MsnGuardVpnService.kt").read_text()
CARD = (APP / "GoolCard.kt").read_text()
STRINGS = (APP / "Strings.kt").read_text()
RUSSIAN = (APP / "RussianStrings.kt").read_text()
ENGINE = (ROOT / "core/aether/src/lib.rs").read_text()


class WgOverMasqueContract(unittest.TestCase):
    def test_pref_defaults_off(self):
        # Plain wireguard is the shipped state; the carrier is opt-in and
        # remembered across connects.
        self.assertIn('const val WG_OVER_MASQUE_PREF = "wireguard_over_masque"', CORE)
        self.assertIn("const val WG_OVER_MASQUE_DEFAULT = false", CORE)
        self.assertIn("fun wgOverMasque(context: Context): Boolean", CORE)
        self.assertIn(
            "context.profiled().getBoolean(WG_OVER_MASQUE_PREF, WG_OVER_MASQUE_DEFAULT)",
            CORE,
        )

    def test_armed_wireguard_maps_to_the_gool_engine_path(self):
        # The whole feature rides the armed-WoW path: json()/env() rewrite the
        # protocol to "gool" so the engine runs wireguard inside the masque
        # tunnel. There is no separate wireguard carrier in the engine.
        self.assertIn(
            'originalProtocol == "wireguard" && wgOverMasque(context) -> "gool"',
            CORE,
        )
        # The null-protocol entry points (tile, quick reconnect) must not
        # silently run plain wireguard over an armed card.
        self.assertIn(
            '(protocol == "wireguard" ||\n                (protocol == null && text("default_protocol", "wireguard") == "wireguard")) &&\n                wgOverMasque(context) -> "gool"',
            CORE,
        )
        # The carrier flag both cards share: every goolOverMasqueArmed gate in
        # env() (forced-peer, manual endpoint, masque-shaped env, WIW inner)
        # must cover the WireGuard carrier too.
        self.assertIn(
            """        val masqueCarrierArmed =
            (originalProtocol == "gool" && goolOverMasque(context)) ||
            (originalProtocol == "wireguard" && wgOverMasque(context))""",
            CORE,
        )
        self.assertNotIn("goolOverMasqueArmed", CORE)
        # The engine arm is the shared, unchanged one.
        self.assertIn("Protocol::WarpInWarp if !gool_classic()", ENGINE)

    def test_the_classic_pin_stays_disarmed_only(self):
        # AETHER_GOOL_MODE=classic must only be pinned when the user turned
        # the foreign exit OFF — an armed WireGuard connect inherits the same
        # gate as the armed WoW connect.
        self.assertIn('if (effectiveProtocol == "gool" && !masqueCarrierArmed)', CORE)
        self.assertEqual(CORE.count('out["AETHER_GOOL_MODE"] = "classic"'), 1)

    def test_armed_wireguard_relays_the_outer_masque_identity(self):
        # Fresh install, WireGuard armed, no masque identity yet: the app must
        # relay it through the engine process exactly like armed WoW
        # (3.2.40: the direct registration never answers on Iranian
        # networks → watchdog → MTU retry loop).
        self.assertIn('relayProtocol == "gool" &&', SERVICE)
        self.assertIn(
            "(CoreConfig.goolOverMasque(this@MsnGuardVpnService) ||\n                        CoreConfig.wgOverMasque(this@MsnGuardVpnService))",
            SERVICE,
        )
        self.assertIn('"Identity relay: masque stored (Gool over MASQUE)"', SERVICE)

    def test_service_treats_the_armed_run_as_a_masque_run(self):
        # No forced gateway (the exit follows the inner registration) and the
        # session endpoint reads the masque lastconn — both gates must cover
        # the WireGuard carrier.
        self.assertIn(
            '(CoreConfig.goolOverMasque(this) || CoreConfig.wgOverMasque(this)))',
            SERVICE,
        )
        self.assertIn(
            'if (CoreConfig.goolOverMasque(this) || CoreConfig.wgOverMasque(this)) File(filesDir, "aether-masque-lastconn.toml")',
            SERVICE,
        )
        # The label must not lie: an armed WireGuard session runs the gool
        # engine path, and prettyProtocol would print WoW — name the transport
        # the user picked instead.
        self.assertIn(
            'currentProtocol.contains("GOOL") && CoreConfig.wgOverMasque(this) -> Strings.t("WireGuard")',
            SERVICE,
        )

    def test_slot_card_is_wired_for_the_wireguard_transport(self):
        # The carrier view is shared with WoW; only strings and pref differ.
        self.assertIn("private lateinit var wgOverMasqueCard: GoolCard", UI)
        self.assertIn('title = Strings.t("WIREGUARD OVER MASQUE")', UI)
        self.assertIn('name = "WireGuard over Masque",', UI)
        self.assertIn("renderWgOverCard()", UI)
        self.assertIn("private fun renderWgOverCard()", UI)
        self.assertIn("applies = selectedProtocol == Protocol.WIREGUARD", UI)
        self.assertIn("private fun setWgOverArmed(armed: Boolean)", UI)
        self.assertIn("putBoolean(CoreConfig.WG_OVER_MASQUE_PREF, armed)", UI)
        # Exactly one slot occupant visible: WireGuard hands the slot to the
        # carrier card, and the chain card stays out of it.
        self.assertIn(
            "val wireguardSelected = selectedProtocol == Protocol.WIREGUARD", UI
        )
        self.assertIn(
            "chainCard.visibility = if (!shardSelected && !masqueSelected && !wowSelected && !wireguardSelected) View.VISIBLE else View.GONE",
            UI,
        )
        self.assertIn(
            "wgOverMasqueCard.visibility = if (wireguardSelected) View.VISIBLE else View.GONE",
            UI,
        )
        # The shared card view is parameterized; the WoW defaults stay intact.
        self.assertIn(
            'private val title: String = Strings.t("GOOL OVER MASQUE"),', CARD
        )
        self.assertIn('text = title', CARD)
        self.assertIn("setArmed(false)", CARD)

    def test_plain_wireguard_is_untouched(self):
        # The narrowest fix: disarmed, the mapping never fires — json() keeps
        # "wireguard" as-is, env() pins nothing new, no WIW/MIM variable is
        # set, and the engine keeps its plain wireguard run. Both mapping
        # sites are gated on the pref, and every gate in env() sits behind
        # the shared masqueCarrierArmed flag (plain wireguard fails both
        # original-protocol checks in it).
        self.assertIn('originalProtocol == "wireguard" && wgOverMasque(context) -> "gool"', CORE)
        self.assertIn('(protocol == "wireguard" ||', CORE)
        self.assertEqual(CORE.count('out["AETHER_GOOL_MODE"] = "classic"'), 1)
        self.assertIn('(effectiveProtocol == "gool" && masqueCarrierArmed)', CORE)

    def test_the_original_selection_rides_along(self):
        # 3.2.45 field log: json's protocol field said "gool" for an armed
        # WireGuard run, so envFromEffectiveConfig passed "gool" to env(),
        # which read the WoW card's pref — OFF — pinned AETHER_GOOL_MODE=classic
        # and the run connected through classic warp-in-warp with an IR exit
        # instead of the masque carrier. The original selection now rides
        # along and envFromEffectiveConfig prefers it.
        self.assertIn(
            'if (effectiveProtocol == "gool" &&\n                (protocol ?: text("default_protocol", "wireguard")) == "wireguard"\n            ) {\n                put("selected_protocol", "wireguard")\n            }',
            CORE,
        )
        self.assertIn(
            'val selected = json.optString("selected_protocol").ifBlank { proto }',
            CORE,
        )
        self.assertIn("protocol = selected,", CORE)
        # The forced-peer injection gate covers either carrier card too.
        self.assertIn(
            '''            val carrierArmed = (selected == "gool" && goolOverMasque(context)) ||
                (selected == "wireguard" && wgOverMasque(context))
            if (!carrierArmed) {''',
            CORE,
        )

    def test_strings_exist_in_every_locale_column(self):
        for key in (
            "WIREGUARD OVER MASQUE",
            "plain wireguard, a local exit",
            "only for the WireGuard transport",
        ):
            row = STRINGS.split(f'"{key}" to Triple(', 1)
            self.assertTrue(len(row) > 1, f"missing Strings.kt row: {key}")
            self.assertIn(f'"{key}" to "', RUSSIAN)


if __name__ == "__main__":
    unittest.main()
