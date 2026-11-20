"""Guard the Gool Over MASQUE carrier choice (3.2.38).

Upstream Aether v2.3.0: `--gool` carries the wireguard WARP identity inside
the MASQUE tunnel and registers it THROUGH that tunnel, so the exit address
is foreign rather than local; `--gool-classic` is the wireguard-in-wireguard
run. The engine arm is `Protocol::WarpInWarp if !gool_classic()` — the app
side owns the choice via the gool_over_masque pref, ON by default.
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


class GoolOverMasqueContract(unittest.TestCase):
    def test_engine_arm_is_gated_on_gool_classic_env(self):
        # The mechanism this feature rides: without AETHER_GOOL_MODE=classic
        # (and without any AETHER_WIW_* peer) "gool" IS warp-in-masque with the
        # inner identity registered through the tunnel.
        self.assertIn("Protocol::WarpInWarp if !gool_classic()", ENGINE)
        self.assertIn("fn gool_classic()", ENGINE)
        self.assertIn('"wiw") | Ok("wg") | Ok("classic")', ENGINE)

    def test_pref_defaults_off_and_env_only_pins_classic_when_disarmed(self):
        self.assertIn('const val GOOL_OVER_MASQUE_PREF = "gool_over_masque"', CORE)
        # 3.2.43: default OFF — the classic carrier is the state WoW always
        # connected with; the armed direction is opt-in and remembered.
        self.assertIn("const val GOOL_OVER_MASQUE_DEFAULT = false", CORE)
        self.assertIn("fun goolOverMasque(context: Context): Boolean", CORE)
        # The variable is what flips the engine; it may only be written when
        # the user turned the foreign exit OFF.
        self.assertIn('if (effectiveProtocol == "gool" && !masqueCarrierArmed)', CORE)
        self.assertEqual(CORE.count('out["AETHER_GOOL_MODE"] = "classic"'), 1)

    def test_armed_run_relays_the_outer_masque_identity_on_a_fresh_install(self):
        # 3.2.40 field log (fresh install): the engine provisioned the DEDICATED
        # MASQUE identity directly from the device — the registration API never
        # answered on the user's network (four 20s timeouts → watchdog → MTU
        # retry loop). The app must relay it like every other identity, armed
        # mode only.
        self.assertIn('relayProtocol == "gool" &&', SERVICE)
        self.assertIn("CoreConfig.goolOverMasque(this@MsnGuardVpnService) ||", SERVICE)
        self.assertIn('IdentityProvisioner.hasIdentity(this@MsnGuardVpnService, "masque")',
                      SERVICE)
        self.assertIn('"Identity relay: masque stored (Gool over MASQUE)"', SERVICE)

    def test_gool_over_masque_runs_with_the_masque_shaped_env(self):
        # v4 scan, H2 transport, no aethernoize, ECH off — the same env plain
        # MASQUE gets on this carrier, because the outer hop IS a masque dial.
        self.assertIn(
            '(effectiveProtocol == "gool" && masqueCarrierArmed)',
            CORE,
        )

    def test_no_wiw_peer_leaks_into_the_foreign_exit_run(self):
        # AETHER_WIW_INNER_PEER's mere presence makes the engine's gool_classic()
        # flip the whole run back to wireguard-in-wireguard, so it must be the
        # else-branch only; the over-masque branch names the engine's real
        # inner-peer variable instead.
        # The env() copy (the JSON compat copy earlier in the file also reads
        # the same pref key) — take the LAST occurrence.
        block = CORE.split('text("manual_inner_endpoint")')[-1].split("\n        }", 1)[0]
        self.assertIn('out["AETHER_GOOL_INNER"] = it', block)
        self.assertIn('out["AETHER_WIW_INNER_PEER"] = it', block)
        # The classic-only gate must wrap the manual ENDPOINT too: AETHER_PEER
        # would force a wireguard-style peer into the masque outer dial.
        self.assertRegex(
            CORE,
            r"if \(!masqueCarrierArmed\) \{\s*\n\s*text\(\"manual_endpoint\"\)",
        )
        # And the forced-peer injection sits behind the same gate.
        self.assertIn('if (!(proto == "gool" && goolOverMasque(context)))', CORE)

    def test_stale_carrier_env_is_cleared_between_connects(self):
        # 3.2.39 field log: the engine keeps ONE process env, and the previous
        # connect's AETHER_GOOL_MODE=classic survived into the next ON connect
        # — the engine ran wireguard-in-wireguard again and the exit stayed IR.
        # applyEnv must actively clear every carrier-mode key absent from the
        # new map.
        block = CORE.split("fun applyEnv(map: Map<String, String>)", 1)[1].split("\n    }\n", 1)[0]
        for key in (
            "AETHER_GOOL_MODE", "AETHER_GOOL_INNER",
            "AETHER_WIW_OUTER_PEER", "AETHER_WIW_INNER_PEER", "AETHER_WIW_PEERS",
            "AETHER_MIM_INNER_PEER", "AETHER_PEER", "AETHER_WG_PEER",
            "AETHER_MASQUE_SNI",
        ):
            self.assertIn(f'"{key}"', block)

    def test_foreign_exit_run_gets_the_masque_sni_and_no_ptech_pool(self):
        # The outer hop is an H2 masque handshake: it needs the DPI-bypass SNI
        # masque gets, and must NOT inherit the WG Ptech CIDR/port pool.
        ptech = CORE.split("run {\n            val sm = warpScannerMode(context)", 1)[1].split("return@run", 1)[0]
        self.assertIn("if (isMasqueForEnv) return@run", CORE)
        sni = CORE.split("AETHER_MASQUE_SNI", 1)[1].split("\n        }", 1)[0]
        self.assertIn("if (isMasqueForEnv) {", sni)

    def test_slot_card_is_wired_for_the_wow_transport(self):
        self.assertIn("private lateinit var goolCard: GoolCard", UI)
        self.assertIn("goolCard = GoolCard(this, palette) { armed -> setGoolArmed(armed) }", UI)
        # Exactly one slot occupant visible: WoW hands the slot to the gool card.
        self.assertIn("val wowSelected = selectedProtocol == Protocol.WARP_IN_WARP", UI)
        self.assertIn(
            "chainCard.visibility = if (!shardSelected && !masqueSelected && !wowSelected && !wireguardSelected) View.VISIBLE else View.GONE",
            UI,
        )
        self.assertIn("goolCard.visibility = if (wowSelected) View.VISIBLE else View.GONE", UI)
        self.assertIn("private fun renderGoolCard()", UI)
        self.assertIn("goolCard.setArmed(CoreConfig.goolOverMasque(this))", UI)
        self.assertIn("private fun setGoolArmed(armed: Boolean)", UI)
        self.assertIn("putBoolean(CoreConfig.GOOL_OVER_MASQUE_PREF, armed)", UI)
        # The card's initial paint matches the OFF default; the real state is
        # still painted from the pref at render time, never hardcoded ON.
        self.assertIn("setArmed(false)", CARD)

    def test_strings_exist_in_every_locale_column(self):
        for key in (
            "GOOL OVER MASQUE",
            "only for the WoW transport",
            "foreign exit — the identity registers through the tunnel",
            "classic: wireguard in wireguard, a local exit",
        ):
            row = STRINGS.split(f'"{key}" to Triple(', 1)
            self.assertTrue(len(row) > 1, f"missing Strings.kt row: {key}")
            self.assertIn(f'"{key}" to "', RUSSIAN)

    def test_service_does_not_force_a_gateway_on_the_foreign_exit(self):
        # The exit-country chase forces WG-style peers; in gool-over-masque the
        # exit follows the inner registration, so the chase stays classic-only.
        self.assertIn(
            'if (sessionExitCountry != null && (currentProtocol != "GOOL" ||',
            SERVICE,
        )
        self.assertIn("CoreConfig.goolOverMasque(this) || CoreConfig.wgOverMasque(this)))", SERVICE)
        # The session endpoint reads the masque lastconn in over-masque mode
        # (run_masque saves there), the classic gool file otherwise.
        self.assertIn(
            'if (CoreConfig.goolOverMasque(this) || CoreConfig.wgOverMasque(this)) File(filesDir, "aether-masque-lastconn.toml")',
            SERVICE,
        )


if __name__ == "__main__":
    unittest.main()
