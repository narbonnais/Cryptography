"""
This is a simple implementation of an IoT temperature averaging system using MPC.
It uses the Paillier cryptosystem to encrypt the temperatures of the devices.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from paillier import generate_keypair, encrypt, decrypt, homomorphic_add, homomorphic_multiply_constant


@dataclass
class CryptoSystem:
    public_key: Tuple[int, int]
    private_key: Tuple[int, int, int]


class IoTDevice:
    def __init__(self, device_id: int, temperature: int):
        self.device_id = device_id
        self.temperature = temperature
        self.encrypted_temperature: Optional[int] = None

    def encrypt_temperature(self, public_key: Tuple[int, int]):
        """Encrypt the device's temperature using the network's public key"""
        self.encrypted_temperature = encrypt(self.temperature, public_key)

    def update_temperature(self, new_temperature: int, public_key: Tuple[int, int]):
        """Update the device's temperature and re-encrypt it"""
        self.temperature = new_temperature
        self.encrypt_temperature(public_key)


class IoTNetwork:
    def __init__(self):
        self.devices: Dict[int, IoTDevice] = {}  # device_id -> IoTDevice
        self.crypto: Optional[CryptoSystem] = None
        # Initialize crypto system once at network creation
        self.initialize_crypto()

    def initialize_crypto(self):
        """Initialize the cryptographic system"""
        public_key, private_key = generate_keypair(key_bits=1024)
        self.crypto = CryptoSystem(public_key, private_key)

    def get_public_key(self) -> Optional[Tuple[int, int]]:
        """Get the network's public key for devices to encrypt their data"""
        return self.crypto.public_key if self.crypto else None

    def device_joins(self, device: IoTDevice):
        """Handle a new device joining the network"""
        self.devices[device.device_id] = device
        
        # Just encrypt the new device's temperature with existing key
        if self.crypto:
            device.encrypt_temperature(self.crypto.public_key)
        
        print(f"Device {device.device_id} joined with encrypted temperature")

    def device_leaves(self, device_id: int):
        """Handle a device leaving the network"""
        if device_id in self.devices:
            del self.devices[device_id]
            print(f"Device {device_id} left the network")

    def device_updates_temperature(self, device: IoTDevice):
        """Update the temperature for a device"""
        if device.device_id not in self.devices:
            print(f"Error: Device {device.device_id} not in network")
            return

        self.devices[device.device_id] = device
        print(f"Device {device.device_id} updated temperature")

    def compute_average_temperature(self) -> Optional[float]:
        """Compute the average temperature across all devices"""
        if not self.devices:
            print("No devices in network")
            return None

        if not self.crypto:
            print("Crypto system not initialized")
            return None

        # Sum all encrypted temperatures
        encrypted_temps = [
            device.encrypted_temperature for device in self.devices.values()]
        encrypted_sum = encrypted_temps[0]
        for encrypted_temp in encrypted_temps[1:]:
            encrypted_sum = homomorphic_add(
                encrypted_sum, encrypted_temp, self.crypto.public_key)

        # Multiply by 1/n to get average
        n = len(self.devices)

        # Decrypt the resulted sum and divide by n to get the average
        decrypted_sum = decrypt(encrypted_sum, self.crypto.private_key)
        average = decrypted_sum / n
        
        return average


def main():
    # Example usage
    print("Starting IoT temperature averaging system...")

    network = IoTNetwork()

    # Create devices with their temperatures
    device1 = IoTDevice(1, 20)  # 20°C
    device2 = IoTDevice(2, 22)  # 22°C
    device3 = IoTDevice(3, 24)  # 24°C

    # Add devices to network
    network.device_joins(device1)
    network.device_joins(device2)
    network.device_joins(device3)

    # Compute and print average
    avg = network.compute_average_temperature()
    print(f"Average temperature: {avg}°C")

    # Update a temperature
    device2.update_temperature(23, network.get_public_key())
    network.device_updates_temperature(device2)

    # Compute new average
    avg = network.compute_average_temperature()
    print(f"New average temperature: {avg}°C")

    # Remove a device and observe key refresh
    network.device_leaves(3)

    # Compute final average
    avg = network.compute_average_temperature()
    print(f"Final average temperature: {avg}°C")


if __name__ == "__main__":
    main()
