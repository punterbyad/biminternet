async function makePayment() {
    // Collecting dynamic values from the form
    const amount = document.getElementById("finalAmount").value;
    const email = document.getElementById("email").value;
    const name = document.getElementById("name").value;

    // Generate a unique transaction reference
    const tx_ref = "bim-" + Math.random().toString(36).substring(2, 15);

    // Fetching the user's IP address
    let customer_id = "Unknown IP"; // Default IP if not available
    try {
      const response = await fetch("https://api.ipify.org?format=json");
      const data = await response.json();
      customer_id = data.ip; // IP address from the API
    } catch (error) {
      console.error("Failed to retrieve IP address:", error);
    }

    // Placeholder for MAC address (not accessible directly in the browser)
    // const customer_mac = "MAC_ADDRESS"; // Replace with backend logic if needed

    // Initialize Flutterwave Checkout
    FlutterwaveCheckout({
      public_key: "FLWPUBK-63cd56385c74cc6020689f531c8afeb5-X",
      tx_ref: tx_ref,
      amount: amount,
      currency: "UGX",
      payment_options: "mobilemoneyuganda",
      redirect_url: "https://bim.choicefinance.group/payment/callback",
      meta: {
    consumer_id: customer_id, // IP Address
    // consumer_mac: customer_mac, // MAC Address
      },
      customer: {
    email: email,
    name: name,
      },
      customizations: {
    title: "Hostel Wifi",
    description: "Payment for Wifi Access",
    logo: "https://www.scan2verify.com/wp-content/uploads/2024/01/cropped-us-logo-favicon-32x32.png",
      },
    });
  }
