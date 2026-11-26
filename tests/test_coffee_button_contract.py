import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "app/src/main/java/com/msnguard/vpn/MainActivity.kt").read_text()


class CoffeeButtonContract(unittest.TestCase):
    """3.4.19: the buy-a-coffee page. The user's spec, pinned:
    - a row under Donate in About, Persian in every language,
    - the exact Persian message,
    - the accept button «باشه مهمونت میکنم» styled like the Foxy Status
      button with a blue ring,
    - the tap opens https://daramet.com/MSN.GUARD in the phone browser.
    The Persian strings must NEVER be routed through Strings.t — in any
    language the page reads Persian."""

    def test_about_lists_the_coffee_row_under_donate(self):
        donate = MAIN.find('navRow(Strings.t("Donate")')
        self.assertGreater(donate, 0)
        coffee = MAIN.find('navRow("یک فنجان قهوه ☕"')
        self.assertGreater(coffee, donate, "coffee row must sit under Donate")

    def test_coffee_strings_are_never_translated(self):
        for persian in ['یک فنجان قهوه ☕', 'باشه مهمونت میکنم',
                        'برنامه MSN-GUARD همیشه رایگانه، و رایگان می‌مونه']:
            self.assertIn(persian, MAIN)
            self.assertNotIn(f'Strings.t("{persian}', MAIN,
                             f"'{persian[:12]}…' went through Strings.t — it would be translated")

    def test_the_button_opens_daramet(self):
        self.assertIn('openCoffeeLink()', MAIN)
        self.assertIn('openLink("https://daramet.com/MSN.GUARD")', MAIN)

    def test_the_button_has_the_blue_ring_and_foxy_shape(self):
        # same helpers the Foxy page buttons use; ring = transparent fill +
        # neonBlue stroke, 44dp tall, radius 10.
        btn = MAIN.find('foxyActionButton("باشه مهمونت میکنم", true)')
        self.assertGreater(btn, 0)
        block = MAIN[btn:btn + 400]
        self.assertIn('palette.neonBlue', block)
        self.assertIn('roundedBackground(Color.TRANSPARENT, 10, palette.neonBlue, 2)', block)

    def test_page_is_back_handled_like_every_other_page(self):
        self.assertIn('private var coffeePage: View? = null', MAIN)
        self.assertIn('coffeePage != null -> closeCoffeeScreen()', MAIN)


if __name__ == "__main__":
    unittest.main()
