import time
from panda.python.uds import UdsClient, SERVICE_TYPE, IsoTpMessage, NegativeResponseError, InvalidServiceIdError

class RobustUdsClient(UdsClient):
    def _uds_request(self, service_type: SERVICE_TYPE, subfunction: int | None = None, data: bytes | None = None) -> bytes:
        """Override the _uds_request method to be more tolerant of unexpected messages"""
        req = bytes([service_type])
        if subfunction is not None:
            req += bytes([subfunction])
        if data is not None:
            req += data

        # send request, wait for response
        max_len = 8 if self.sub_addr is None else 7
        isotp_msg = IsoTpMessage(self._can_client, timeout=self.timeout, debug=self.debug, max_len=max_len)
        isotp_msg.send(req)

        # Keep trying until we get a valid response or timeout
        start_time = time.time()
        response_pending = False

        while True:
            timeout = self.response_pending_timeout if response_pending else self.timeout
            if time.time() - start_time > self.timeout * 3:  # Overall timeout
                raise Exception("Timeout waiting for valid response")

            resp, _ = isotp_msg.recv(timeout)
            if resp is None:
                continue

            response_pending = False
            resp_sid = resp[0] if len(resp) > 0 else None

            # Handle negative response
            if resp_sid == 0x7F:
                service_id = resp[1] if len(resp) > 1 else -1
                error_code = resp[2] if len(resp) > 2 else -1

                # Only process negative responses for our request
                if service_id == service_type:
                    # Wait for another message if response pending
                    if error_code == 0x78:
                        response_pending = True
                        if self.debug:
                            print("UDS-RX: response pending")
                        continue

                    # Handle actual error
                    try:
                        from panda.python.uds import _negative_response_codes
                        error_desc = _negative_response_codes.get(error_code, f"Unknown error: {error_code}")
                    except:
                        error_desc = f"Error code: {error_code}"

                    raise NegativeResponseError(f"Service {hex(service_id)} - {error_desc}", service_id, error_code)
                else:
                    # Negative response for a different service, ignore it
                    continue

            # check if it's a response to our request
            expected_sid = service_type + 0x40
            if resp_sid == expected_sid:
                # Valid response for our service
                if subfunction is not None:
                    resp_sfn = resp[1] if len(resp) > 1 else None
                    if subfunction != resp_sfn:
                        if self.debug:
                            print(f"Ignoring response with incorrect subfunction: {hex(resp_sfn) if resp_sfn is not None else None}")
                        continue

                # Return data (exclude service id and sub-function id)
                return resp[(1 if subfunction is None else 2):]
            else:
                # Response for a different service, ignore it
                if self.debug:
                    print(f"Ignoring response with unexpected service ID: {hex(resp_sid) if resp_sid is not None else None}")
                continue
