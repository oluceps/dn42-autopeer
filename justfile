set shell := ["nu", "-c"]

export DATABASE_URL := env_var_or_default("DATABASE_URL", "postgres://dummy:dummy@127.0.0.1:5432/dummy")
export BIRD_CONF_DIR := env_var_or_default("BIRD_CONF_DIR", "/tmp/dn42-peers")

# Start local PostgreSQL container (for local development and testing)
db-up:
    print "Starting local test database container..."
    podman run --replace --rm -d --name dn42-test-db -e POSTGRES_PASSWORD=dummy -e POSTGRES_USER=dummy -p 5432:5432 docker.io/library/postgres:15-alpine
    print "Waiting for database initialization..."
    sleep 3sec

# Stop local PostgreSQL container
db-down:
    print "Stopping and removing local test database container..."
    podman stop dn42-test-db | ignore

# Run the server locally for development
dev: db-up
    print "Starting local development server..."
    env DATABASE_URL="postgres://dummy:dummy@localhost/dummy" BIRD_CONF_DIR="./tests/bird_conf" cargo run

# Run E2E API tests (CRUD)
test-api:
    #!/usr/bin/env nu
    
    # ======== Environment Setup ========
    let test_dir = "/tmp/dn42-peers-test"
    mkdir $test_dir
    
    print "========== [0] Start Test Server =========="
    # Start the application in the background (debug mode automatically skips the challenge)
    # Force logs to /tmp/autopeer_test.log for troubleshooting
    
    # Build first to avoid timeout during cargo run compilation
    print "Building binary..."
    bash -c 'cargo build'
    
    # Start Mock Registry API
    print "Starting Mock Registry API..."
    bash -c 'python3 mock_registry.py > /tmp/mock_registry.log 2>&1 &'
    
    # Wait for the Mock Registry to initialize
    sleep 1sec
    
    # We use cargo run to compile and start the server inside the container environment.
    bash -c 'env REGISTRY_API_URL="http://127.0.0.1:8081" BIRD_CONF_DIR="/tmp/dn42-peers-test" cargo run > /tmp/autopeer_test.log 2>&1 &'
    
    # Wait for the server to initialize and bind the port
    sleep 3sec
    
    # Get the PID of the background process
    let server_pid = (bash -c 'pgrep -f "target/debug/nyaw-dn42-autopeer" | head -n1' | str trim)
    if ($server_pid == "") {
        print "Server failed to start! Please check /tmp/autopeer_test.log"
        cat /tmp/autopeer_test.log
        exit 1
    }
    print $"Server started in background, PID: ($server_pid)"

    # ======== Business Logic Tests ========
    try {
        print "========== [1] Create Peer =========="
        let create_payload = '{"asn": 4242421234, "pubkey": "q1z/aK6XjHhKxXjVvV/5lD9hW2l8aU+21u6Vz9+Y1gQ=", "endpoint": "198.51.100.1:51820", "challenge": { "auth": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOBz+SBn8O1744J1XQ3OpwIGmXnkWR9u8prAF5GfIL0B", "signature": "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg4HP5IGfw7XvjgnVdDc6nAgaZee\nRZH27ymsAXkZ8gvQEAAAAEZG40MgAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx\nOQAAAEBjZYSC/ZKn0OOd1vVVbjcTCtSZrAiZn1qn1ULuMTLC9jpOvMpMAeWi1klxvBpRq6\nisLKZQnKp5gsQyeSQeu2AM\n-----END SSH SIGNATURE-----" }}'
        let res = (curl -s -X POST -H "Content-Type: application/json" -d $create_payload http://127.0.0.1:8080/api/peers | from json)
        print $res

        print "========== [2] Check BIRD Template Output =========="
        print "Config directory contents:"
        ls $test_dir
        print "Config file contents:"
        cat $"($test_dir)/wg4242421234.conf"

        print "========== [3] Update Peer (Endpoint Roaming) =========="
        let update_payload = '{"asn": 4242421234, "pubkey": "q1z/aK6XjHhKxXjVvV/5lD9hW2l8aU+21u6Vz9+Y1gQ=", "endpoint": "203.0.113.1:51820", "challenge": { "auth": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOBz+SBn8O1744J1XQ3OpwIGmXnkWR9u8prAF5GfIL0B", "signature": "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg4HP5IGfw7XvjgnVdDc6nAgaZee\nRZH27ymsAXkZ8gvQEAAAAEZG40MgAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx\nOQAAAEBjZYSC/ZKn0OOd1vVVbjcTCtSZrAiZn1qn1ULuMTLC9jpOvMpMAeWi1klxvBpRq6\nisLKZQnKp5gsQyeSQeu2AM\n-----END SSH SIGNATURE-----" }}'
        let res = (curl -s -X PATCH -H "Content-Type: application/json" -d $update_payload http://127.0.0.1:8080/api/peers | from json)
        print $res

        print "========== [4] Check Database State =========="
        print "1. Postgres Database state verification:"
        psql $env.DATABASE_URL -c "SELECT asn, endpoint, status FROM peers WHERE asn = 4242421234;"
        print "2. Background application logs (Observability):"
        tail -n 10 /tmp/autopeer_test.log

        print "========== [5] Delete Peer =========="
        let delete_payload = '{"asn": 4242421234, "challenge": { "auth": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOBz+SBn8O1744J1XQ3OpwIGmXnkWR9u8prAF5GfIL0B", "signature": "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg4HP5IGfw7XvjgnVdDc6nAgaZee\nRZH27ymsAXkZ8gvQEAAAAEZG40MgAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx\nOQAAAEA30znxGld2LXXnl4sfr/CBaLkWS55AEuIJQy86kN8a0GFf1HVWFDzn2lINgr+Ig6\nxBmJALo8VfppQGMjm5arAK\n-----END SSH SIGNATURE-----" }}'
        let res = (curl -s -X DELETE -H "Content-Type: application/json" -d $delete_payload http://127.0.0.1:8080/api/peers | from json)
        print $res
        
        print "========== [6] Verify Deletion (RAII & Cleanup) =========="
        let files = (ls $test_dir)
        if ($files | length) == 0 {
            print "BIRD config file successfully cleaned up by business logic!"
        } else {
            print "Error: BIRD config file remains!"
            exit 1
        }
        print "========== [7] Create Peer (PGP) =========="
        let create_pgp_payload = '{"asn": 4242421235, "pubkey": "q1z/aK6XjHhKxXjVvV/5lD9hW2l8aU+21u6Vz9+Y1gQ=", "endpoint": "198.51.100.1:51820", "challenge": { "auth": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEaqWnfhYJKwYBBAHaRw8BAQdAVyDefHkGMSErwbsW6giD0PHqgLVKkgFYgfHr\nbPgolu60GURONDIgVGVzdCA8dGVzdEBkbjQyLmRldj6IkwQTFgoAOxYhBGs0Uh+C\nnaNVaXTFjcuajMSFZ1oOBQJqpad+AhsjBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4H\nAheAAAoJEMuajMSFZ1oOAdsA/itG0iSJvLEfP103cI0wEBu5rrssHxzSZEtI30Qi\nwr+FAP95mumWjux4BsA/lsUTZnUAiLeBi7tw9MTDohJLilxyArg4BGqlp34SCisG\nAQQBl1UBBQEBB0Dvp89SMsGAVStTlRL2hBYqWpnVFbRa49m4kShHEDTocQMBCAeI\neAQYFgoAIBYhBGs0Uh+CnaNVaXTFjcuajMSFZ1oOBQJqpad+AhsMAAoJEMuajMSF\nZ1oOj+oA/RogQXmcPUNkUo2qw6OdH6xT2fex9lMxw6XTnkrT5EKlAQDIOmmNREGj\nbmKAfld55Td5rgywwyIUMrXtco/vvt8QDg==\n=e9fb\n-----END PGP PUBLIC KEY BLOCK-----", "signature": "-----BEGIN PGP SIGNATURE-----\n\niHUEABYKAB0WIQRrNFIfgp2jVWl0xY3LmozEhWdaDgUCaqWnmQAKCRDLmozEhWda\nDhBRAP4gFRmHOs4bXtagTTumSMKnsz5gSApOzrC24OoDYr8OXwEAqwU1WNGtBX/Q\nr1iOf8lVq5A8Jt/EAJ2WBZlanBzsdwY=\n=KXOQ\n-----END PGP SIGNATURE-----" }}'
        let res = (curl -s -X POST -H "Content-Type: application/json" -d $create_pgp_payload http://127.0.0.1:8080/api/peers | from json)
        print $res

        print "========== [8] Delete Peer (PGP) =========="
        let delete_pgp_payload = '{"asn": 4242421235, "challenge": { "auth": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEaqWnfhYJKwYBBAHaRw8BAQdAVyDefHkGMSErwbsW6giD0PHqgLVKkgFYgfHr\nbPgolu60GURONDIgVGVzdCA8dGVzdEBkbjQyLmRldj6IkwQTFgoAOxYhBGs0Uh+C\nnaNVaXTFjcuajMSFZ1oOBQJqpad+AhsjBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4H\nAheAAAoJEMuajMSFZ1oOAdsA/itG0iSJvLEfP103cI0wEBu5rrssHxzSZEtI30Qi\nwr+FAP95mumWjux4BsA/lsUTZnUAiLeBi7tw9MTDohJLilxyArg4BGqlp34SCisG\nAQQBl1UBBQEBB0Dvp89SMsGAVStTlRL2hBYqWpnVFbRa49m4kShHEDTocQMBCAeI\neAQYFgoAIBYhBGs0Uh+CnaNVaXTFjcuajMSFZ1oOBQJqpad+AhsMAAoJEMuajMSF\nZ1oOj+oA/RogQXmcPUNkUo2qw6OdH6xT2fex9lMxw6XTnkrT5EKlAQDIOmmNREGj\nbmKAfld55Td5rgywwyIUMrXtco/vvt8QDg==\n=e9fb\n-----END PGP PUBLIC KEY BLOCK-----", "signature": "-----BEGIN PGP SIGNATURE-----\n\niHUEABYKAB0WIQRrNFIfgp2jVWl0xY3LmozEhWdaDgUCaqWnmQAKCRDLmozEhWda\nDo8kAPwOBmzznhsMfdFVyTymawtMnyj67uXVXvNmKk78E2T55wEAiDWV5DJYmBWV\nvr8YdKOna4YgzdUmq9zwDbTFl/NKsQo=\n=DhYC\n-----END PGP SIGNATURE-----" }}'
        let res = (curl -s -X DELETE -H "Content-Type: application/json" -d $delete_pgp_payload http://127.0.0.1:8080/api/peers | from json)
        print $res

    } catch { |err|
        print $"Test encountered an error: ($err)"
        bash -c $"kill -TERM ($server_pid) || true"
        exit 1
    }
    
    # ======== Environment Cleanup ========
    print "========== [7] Terminate Server and Test RAII =========="
    # Send SIGTERM to trigger Axum graceful shutdown and PeerManager Drop
    bash -c $"kill -TERM ($server_pid) || true"
    print "Waiting for server graceful shutdown and Drop resource reclamation..."
    sleep 2sec
    
    # Check if the server executed cleanup in its final logs
    print "Server shutdown logs:"
    tail -n 10 /tmp/autopeer_test.log

# Build test container image
build-test-image:
    print "Building test container image..."
    podman build -t dn42-autopeer-test -f Dockerfile.test .

# Run E2E test suite fully containerized
test: build-test-image
    #!/usr/bin/env nu
    print "Setting up test network..."
    podman network create dn42-test-net | ignore
    
    print "Starting local test database container..."
    podman run --rm -d --name dn42-test-db --network dn42-test-net -e POSTGRES_PASSWORD=dummy -e POSTGRES_USER=dummy docker.io/library/postgres:15-alpine
    sleep 3sec
    
    print "Running API tests in isolated Rust container..."
    let exit_code = (try {
        podman run --rm --network dn42-test-net -v (pwd):/workspace -e DATABASE_URL="postgres://dummy:dummy@dn42-test-db:5432/dummy" dn42-autopeer-test just test-api
        0
    } catch { 1 })
    
    print "Cleaning up test environment..."
    podman stop dn42-test-db | ignore
    podman network rm dn42-test-net | ignore
    
    if $exit_code != 0 { exit 1 }

# CI alias that builds the project and runs the test suite
ci-test:
    just test
