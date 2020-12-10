from src.util.oracle.coins import Currency, Coin
from src.util.oracle.oracle import Oracle


def test_price_oracle():
    oracle = Oracle()

    coin = Coin.Uniswap
    currency = Currency.USD

    price = oracle.price(coin, currency)
    print(price)
    assert isinstance(price, float)

    gas_price = oracle.gas_price()
    print(gas_price)
    assert isinstance(price, float)
