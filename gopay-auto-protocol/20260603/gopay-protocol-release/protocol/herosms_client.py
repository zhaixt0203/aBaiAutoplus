import time, re, requests

class HeroSMS:
    def __init__(self, api_key, base='https://hero-sms.com/stubs/handler_api.php'):
        self.api_key = api_key
        self.base = base
        self.s = requests.Session()

    def _get(self, action, **params):
        p = {'api_key': self.api_key, 'action': action}
        p.update(params)
        r = self.s.get(self.base, params=p, timeout=30)
        r.raise_for_status()
        return r.text.strip()

    def balance(self):
        res = self._get('getBalance')
        if res.startswith('ACCESS_BALANCE'):
            return {'balance': res.split(':')[1]}
        return {'raw': res}

    def buy(self, service='ni', country=6, max_price=None):
        # HeroSMS uses standard sms-activate API.
        # 'ni' is Gojek. '6' is Indonesia.
        res = self._get('getNumber', service=service, country=country)
        if res.startswith('ACCESS_NUMBER'):
            parts = res.split(':')
            # format: ACCESS_NUMBER:$id:$number
            return {'id': parts[1], 'phoneNumber': parts[2]}
        if res == 'NO_NUMBERS':
            raise RuntimeError('HeroSMS buy failed: NO_NUMBERS (库存不足)')
        if res == 'NO_BALANCE':
            raise RuntimeError('HeroSMS buy failed: NO_BALANCE (余额不足)')
        raise RuntimeError(f'HeroSMS buy failed: {res}')

    def cancel(self, order_id):
        res = self._get('setStatus', status=8, id=order_id)
        return {'raw': res}

    def finish(self, order_id):
        res = self._get('setStatus', status=6, id=order_id)
        return {'raw': res}

    def request_next_code(self, order_id):
        res = self._get('setStatus', status=3, id=order_id)
        return {'raw': res}

    def sync(self, order_id):
        return self._get('getStatus', id=order_id)

    def poll_code(self, order_id, timeout=1200, interval=5):
        end = time.time() + timeout
        last = None
        while time.time() < end:
            res = self.sync(order_id)
            last = res
            if res.startswith('STATUS_OK'):
                # format: STATUS_OK:123456
                code = res.split(':')[1]
                return code, res
            elif res == 'STATUS_WAIT_CODE':
                pass
            elif res == 'STATUS_CANCEL':
                raise RuntimeError(f'Order {order_id} was cancelled by provider')
            
            time.sleep(interval)
        raise TimeoutError(f'no sms code for {order_id}; last={last!r}')
