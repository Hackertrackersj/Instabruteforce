# Copyright 2015-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

import stem.response


class AddOnionResponse(stem.response.ControlMessage):
  """
  ADD_ONION response.

  :var str service_id: hidden service address without the '.onion' suffix
  :var str private_key: base64 encoded hidden service private key
  :var str private_key_type: crypto used to generate the hidden service private
    key (such as RSA1024)
  :var dict client_auth: newly generated client credentials the service accepts
  """

  def _parse_message(self):
    # Example:
    #   250-ServiceID=gfzprpioee3hoppz
    #   250-PrivateKey=RSA1024:MIICXgIBAAKBgQDZvYVxv...
    #   250-ClientAuth=bob:l4BT016McqV2Oail+Bwe6w
    #   250 OK

    self.service_id = None
    self.private_key = None
    self.private_key_type = None
    self.client_auth = {}

    if not self.is_ok():
      raise stem.ProtocolError("ADD_ONION response didn't have an OK status: %s" % self)

    if not str(self).startswith('ServiceID='):
      raise stem.ProtocolError('ADD_ONION response should start with the service id: %s' % self)

    for line in list(self):
      if '=' in line:
        key, value = line.split('=', 1)

        if key == 'ServiceID':
          self.service_id = value
        elif key == 'PrivateKey':
          if ':' not in value:
            raise stem.ProtocolError("ADD_ONION PrivateKey lines should be of the form 'PrivateKey=[type]:[key]: %s" % self)

          self.private_key_type, self.private_key = value.split(':', 1)
        elif key == 'ClientAuth':
          if ':' not in value:
            raise stem.ProtocolError("ADD_ONION ClientAuth lines should be of the form 'ClientAuth=[username]:[credential]: %s" % self)

          username, credential = value.split(':', 1)
          self.client_auth[username] = credential
