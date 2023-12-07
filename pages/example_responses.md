# example responses
The API responses are rather expansive, so example responses are documented here.

Since this API's reverse engineered these structures may be subject to change over time.

### Basic test script
You can use this script evaluate responses for yourself.
```elixir
defmodule TestCallback do
  def handle_event(json) do
    IO.inspect(json, label: "Got a websocket message •ᴗ•")
  end
end

Logger.configure(level: :debug)

Kevo.start_link([
  name: Kevo,
  username: System.get_env("KEVO_USER"),
  password: System.get_env("KEVO_PASSWORD"),
  ws_callback_module: TestCallback
])
```

### `Kevo.get_lock/1`
```elixir
%{
  "batteryChargeStatus" => 0,
  "batteryLevel" => 40,
  "batteryLevelCritical" => 0.3,
  "batteryLevelLow" => 0.4,
  "batteryLevelOk" => 0.5,
  "boltState" => "Locked",
  "boltStateTime" => "2023-12-01T19:31:31.557",
  "brand" => "Kwikset",
  "description" => "No Description Set",
  "deviceStates" => [],
  "features" => [
    %{
      "available" => true,
      "feature" => 16,
      "reason" => 0,
      "requiredVersion" => "0.2.3"
    },
    %{
      "available" => true,
      "feature" => 32,
      "reason" => 0,
      "requiredVersion" => "0.2.3"
    },
    %{
      "available" => true,
      "feature" => 64,
      "reason" => 0,
      "requiredVersion" => "0.2.3"
    },
    # ...
    %{
      "available" => true,
      "feature" => 8192,
      "reason" => 0,
      "requiredVersion" => "1.2.14"
    },
    %{
      "available" => true,
      "feature" => 1,
      "reason" => 0,
      "requiredVersion" => "0.2.3"
    },
    %{
      "available" => true,
      "feature" => 2,
      "reason" => 0,
      "requiredVersion" => "0.2.3"
    },
    # ...
  ],
  "firmwareVersion" => "1.9.49",
  "hardwareType" => 4,
  "id" => "95fb0051-da97-468e-8170-c5033156401c",
  "lastHistorySequenceNumber" => 112362,
  "mainsPowerStatus" => 0,
  "name" => "Front Door",
  "permissions" => [
    %{
      "certificate" => "",
      "created" => "2019-12-03T23:08:43.893",
      "deviceDbuToken" => "",
      "deviceVerificationToken" => "",
      "grantee" => %{
        "id" => "89426e98-f370-42a4-a89d-3967b5b2aed4",
        "profile" => %{"firstName" => "Gordon", "lastName" => "Freeman"},
        "username" => "gfreeman@bmesa.org"
      },
      "grantor" => %{
        "id" => "89426e98-f370-42a4-a89d-3967b5b2aed4",
        "profile" => %{"firstName" => "Gordon", "lastName" => "Freeman"},
        "username" => "gfreeman@bmesa.org"
      },
      "id" => "7e0ca53b-34b5-454f-8639-e45e394dbf36",
      "message" => "",
      "name" => "Front Door",
      "status" => "Accepted",
      "type" => "Owner"
    },
    %{
      "certificate" => "",
      "created" => "2019-12-03T23:23:56.673",
      "deviceDbuToken" => "",
      "deviceVerificationToken" => "",
      "grantee" => %{
        "id" => "d05f6193-8ab8-456f-bf1d-3f73acb0f615",
        "profile" => %{"firstName" => "John", "lastName" => "Doe"},
        "username" => "jdoe@anonymous.com"
      },
      "grantor" => %{
        "id" => "89426e98-f370-42a4-a89d-3967b5b2aed4",
        "profile" => %{"firstName" => "Gordon", "lastName" => "Freeman"},
        "username" => "gfreeman@bmesa.org"
      },
      "id" => "984d6a2b-788d-460b-9545-0d0fca6ab418",
      "message" => "",
      "name" => "419", # not always a number, could be any string
      "status" => "Accepted",
      "type" => "Admin"
    },
    %{
      "certificate" => "",
      "created" => "2023-09-14T16:52:34.427",
      "deviceDbuToken" => "",
      "deviceVerificationToken" => "",
      "grantee" => %{
        "id" => "d0776b9d-33c0-497b-841a-01f1c0862979",
        "profile" => %{"firstName" => "Bobby", "lastName" => "Tables"},
        "username" => "btables@drops.com"
      },
      "grantor" => %{
        "id" => "89426e98-f370-42a4-a89d-3967b5b2aed4",
        "profile" => %{"firstName" => "Gordon", "lastName" => "Freeman"},
        "username" => "gfreeman@bmesa.org"
      },
      "id" => "133aa8cc-4035-48f4-b09e-1875dc02bfd2",
      "message" => "",
      "name" => "Front Door",
      "status" => "Accepted",
      "type" => "Guest"
    },
    # ...
    %{
      "certificate" => "redacted",
      "created" => "2023-10-02T16:53:11.283",
      "deviceDbuToken" => "redacted",
      "deviceVerificationToken" => "redacted",
      "grantee" => %{"id" => "64d4dd5d-4600-416f-8518-6a9368a2c1b7"},
      "grantor" => %{
        "id" => "89426e98-f370-42a4-a89d-3967b5b2aed4",
        "profile" => %{"firstName" => "Gordon", "lastName" => "Freeman"},
        "username" => "gfreeman@bmesa.org"
      },
      "id" => "b8b6ccf6-3593-4ec9-9219-06e881073f8c",
      "message" => "",
      "status" => "Accepted",
      "type" => "Device",
      "validFrom" => "2023-10-02T16:53:11",
      "validTo" => "2033-10-02T16:53:11"
    }
  ],
  "productDescriptor" => "DBU2KWK0001",
  "sequenceNumber" => 112368,
  "stats" => %{
    "activePermissions" => 24,
    "availableKeyCount" => 0,
    "disabledPermissions" => 0,
    "lastAccessed" => "2023-12-01T19:38:56.498865Z",
    "maxKeyCount" => 25,
    "openPermissions" => 25,
    "pendingPermissions" => 1,
    "rejectedPermissions" => 0,
    "remainingKeyCount" => 0,
    "revokedPermissions" => 0,
    "totalKeyCount" => 25
  },
  "status" => "Paired",
  "timeOffset" => -5.0,
  "upgradeStatus" => "UpgradeNotAvailable"
}
```

### `Kevo.get_locks/0`
A list of locks following the above schema.

### `Kevo.get_events/3`
Events appear to be in descending order, recent to oldest.

```elixir
%{
  "currentPage" => 1,
  "events" => [
    %{
      "event" => "AutoLock",
      "id" => "1124162023fa1e598d54eaf9eecd6e1387807bac05",
      "target" => "Front Door",
      "timeStamp" => "2023-12-01T19:40:59Z",
      "timeStampLocal" => "2023-12-01T14:40:59"
    },
    %{
      "event" => "Unlock",
      "id" => "1123742023fa1e598d54eaf9eecd6e1387807bac05",
      "performer" => "Walter Clements",
      "target" => "Front Door",
      "timeStamp" => "2023-12-01T19:40:18Z",
      "timeStampLocal" => "2023-12-01T14:40:18"
    },
    # ...
    %{
      "event" => "AutoLock",
      "id" => "1123592023fa1e598d54eaf9eecd6e1387807bac05",
      "target" => "Front Door",
      "timeStamp" => "2023-12-01T19:20:23Z",
      "timeStampLocal" => "2023-12-01T14:20:23"
    },
    %{
      "event" => "ManualUnlock",
      "id" => "1123562023fa1e598d54eaf9eecd6e1387807bac05",
      "target" => "Front Door",
      "timeStamp" => "2023-12-01T19:19:51Z",
      "timeStampLocal" => "2023-12-01T14:19:51"
    },
    # ...
  ],
  "fetchCount" => 10,
  "totalCount" => 1000,
  "totalPages" => 100
}
```

### Websocket events:
Here's a few events in descending order, first toggling the lock via bluetooth, then manually.

*Note: This isn't an exhaustive list.*

```elixir
%{
  "hmac" => "3aZRKZ8z6zqX7F0jic9fQFm1WACtySvYcNuoIHTneeM=",
  "messageData" => %{
    "Nonce" => nil,
    "batteryChargeStatus" => 0,
    "batteryLevel" => 100,
    "boltState" => 2,
    "boltStateTime" => "2023-12-01T20:28:59.6583209",
    "command" => nil,
    "communicationStatus" => 1,
    "communicationStatusTime" => "2023-12-01T20:28:43.963",
    "deviceStates" => [],
    "historySequenceNumber" => 35549,
    "lockId" => "551b8e95-487f-4d8d-9438-70c3b390e4b1",
    "mainsPowerStatus" => 0,
    "sequenceNumber" => 35552,
    "timestamp" => "2023-12-01T20:28:59.7663247"
  },
  "messageLength" => 390,
  "messageType" => "LockStatus"
}
# ...
%{
  "hmac" => "Z4FX64yCYOPZ5sksgCtTNPtamEzTBkH4X8mgJM/keVc=",
  "messageData" => %{
    "Nonce" => nil,
    "batteryChargeStatus" => 0,
    "batteryLevel" => 100,
    "boltState" => 2,
    "boltStateTime" => "2023-12-01T20:28:59.657",
    "command" => nil,
    "communicationStatus" => 1,
    "communicationStatusTime" => "2023-12-01T20:28:43.963",
    "deviceStates" => [],
    "historySequenceNumber" => 35552,
    "lockId" => "551b8e95-487f-4d8d-9438-70c3b390e4b1",
    "mainsPowerStatus" => 0,
    "sequenceNumber" => 35552,
    "timestamp" => "2023-12-01T20:29:01.3667579"
  },
  "messageLength" => 386,
  "messageType" => "LockStatus"
}
# ...
%{
  "hmac" => "fenPmaMK5IuiOg+Kj9+YRr8WiT1EvhCfJwsGkxZeqVM=",
  "messageData" => %{
    "Nonce" => nil,
    "batteryChargeStatus" => 0,
    "batteryLevel" => 100,
    "boltState" => 1,
    "boltStateTime" => "2023-12-01T20:29:08.171172",
    "command" => nil,
    "communicationStatus" => 1,
    "communicationStatusTime" => "2023-12-01T20:28:43.963",
    "deviceStates" => [],
    "historySequenceNumber" => 35552,
    "lockId" => "551b8e95-487f-4d8d-9438-70c3b390e4b1",
    "mainsPowerStatus" => 0,
    "sequenceNumber" => 35559,
    "timestamp" => "2023-12-01T20:29:08.3527448"
  },
  "messageLength" => 389,
  "messageType" => "LockStatus"
}
# ...
%{
  "hmac" => "OvFiALsSLlL+5lV3Q6h/TMPWu1CvxkK5j2Ct07YplQg=",
  "messageData" => %{
    "Nonce" => nil,
    "batteryChargeStatus" => 0,
    "batteryLevel" => 100,
    "boltState" => 1,
    "boltStateTime" => "2023-12-01T20:29:08.17",
    "command" => nil,
    "communicationStatus" => 1,
    "communicationStatusTime" => "2023-12-01T20:28:43.963",
    "deviceStates" => [],
    "historySequenceNumber" => 35559,
    "lockId" => "551b8e95-487f-4d8d-9438-70c3b390e4b1",
    "mainsPowerStatus" => 0,
    "sequenceNumber" => 35559,
    "timestamp" => "2023-12-01T20:29:09.4513288"
  },
  "messageLength" => 385,
  "messageType" => "LockStatus"
}
# ...
%{
  "hmac" => "2sdJ1t/zfwF+ENkQhIgg6MVQ9F34NK+lq9PBXk0t3Us=",
  "messageData" => %{
    "Nonce" => nil,
    "batteryChargeStatus" => 0,
    "batteryLevel" => 100,
    "boltState" => 1,
    "boltStateTime" => "2023-12-01T20:29:08.17",
    "command" => nil,
    "communicationStatus" => 1,
    "communicationStatusTime" => "2023-12-01T20:28:43.963",
    "deviceStates" => [],
    "historySequenceNumber" => 35565,
    "lockId" => "551b8e95-487f-4d8d-9438-70c3b390e4b1",
    "mainsPowerStatus" => 0,
    "sequenceNumber" => 35559,
    "timestamp" => "2023-12-01T20:29:25.513874"
  },
  "messageLength" => 384,
  "messageType" => "LockStatus"
}
```
