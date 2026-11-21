"""Hand-authored opening-turn families for the frozen N2 generator."""

LOOKUPS = (
    "My email is {email}.",
    "The email on my account is {email}.",
    "You can find my account under {email}.",
    "I used {email} for my account.",
    "If you need my email, it's {email}.",
    "I sign in with {email}.",
    "My account is registered to {email}.",
    "Here's the email I use for the store: {email}.",
)
ACCOUNT = (
    "My account ID is {customer}.",
    "My username with the store is {customer}.",
    "My account shows the ID {customer}.",
)
NO_LONGER_NEEDED = (
    "I don't need it anymore.",
    "I no longer have a use for it.",
    "I ended up not needing it.",
)
ORDERED_BY_MISTAKE = (
    "I placed it by mistake.",
    "I ordered it accidentally.",
    "I didn't mean to place that order.",
)

CANCEL = (
    "Could you cancel order {order} for me?",
    "Please call off the purchase under order number {order}.",
    "I'd like to cancel {order}, please.",
    "I'm writing about {order}. Can you cancel that order?",
    "Please go ahead and cancel my order {order}.",
    "I'd appreciate your help canceling order {order}.",
    "Can you put through a cancellation for {order}?",
    "I found the order number in my receipt: {order}. I'd like to cancel it.",
    "Would you help me cancel the order numbered {order}?",
    "I want to cancel my whole order, {order}.",
    "Could you cancel the purchase on my account with order number {order}?",
    "I was checking my orders and found {order}. Please cancel that one.",
)
RETURN = (
    "I'd like to return everything in order {order}. Please refund the original payment method.",
    "Can I send all of {order} back? Please credit whatever I originally paid with.",
    "I'm returning the full contents of {order}. Send the money back where it came from, please.",
    "Please start a return for every item on {order} and refund the method I used to buy it.",
    "I would like to send back the entire order, {order}. I want the refund on the original payment.",
    "Could you take back all the items from {order}? I'd like the refund on the same method I paid with.",
    "Order {order} is the one I'm returning, all of it. Please use the original payment for the refund.",
    "I found the order number on the receipt: {order}. I need to return the lot and be refunded how I paid.",
    "Please set up a return for the whole of order {order}. Put the refund back on the original payment method.",
    "Nothing from {order} worked out for me. I'd like to return every item and be refunded the way I paid.",
    "I want a return for all of order {order}, with the refund sent to the same place my payment came from.",
    "Could I get a return started for every item in {order}? I'd like the original payment method credited.",
)
ADDRESS = (
    "I've moved. Please make {address} the default address on my account.",
    "Please save {address} as my new account address for future purchases.",
    "Could you update the address on my profile to {address}? It's the default address I want changed.",
    "I need my default address changed to {address}. This is for the address saved in my profile.",
    "My new permanent address is {address}. Please update the default on my store account.",
    "Can you set my account's default address to {address}? I want it saved for future orders.",
    "Please replace the default shipping address on my profile with {address}.",
    "I'd like to change where my account defaults to for new orders. Please use {address}.",
    "Could you save a new default for my profile? The address is {address}.",
    "I've got a new mailing address, {address}. Please make that the address saved as my account default.",
    "Please use {address} as my default address going forward. My existing shipments are fine.",
    "I'm updating my profile after a move. Change the saved default address to {address}, please.",
)
MULTI = (
    "I don't have the order number. Please cancel the order {description}.",
    "Could you find and cancel my order {description}?",
    "Please cancel the order {description}. I can't find the receipt right now.",
    "I only remember that it was the order {description}. Can you cancel it?",
    "Could you call off the purchase {description}? I've lost the order number.",
    "I'm trying to cancel my order {description}. Could you help?",
    "I have a few purchases on the account. I want to cancel the one {description}.",
    "Please put through a cancellation for my order {description}.",
    "I don't have the confirmation email handy, but I'd like to cancel the order {description}.",
    "I'm getting in touch about the order {description}. Please cancel it for me.",
    "Could you help with a cancellation? It's for my order {description}.",
    "I want to stop the order {description}. Could you cancel that one?",
)
HANDOFF = (
    "Can you book an in-home repair appointment for my dishwasher?",
    "Could someone arrange a technician to fix my dryer at home?",
    "I'd like to schedule a repair visit for my freezer. Is Tuesday open?",
    "Can you send someone to fix the broken door on my oven?",
    "I'm trying to book a service appointment for my washing machine.",
    "Please arrange a repair appointment for my TV. Could someone come to the house?",
    "I'd like a technician to take a look at my stove. Can you book a visit?",
    "Can you schedule a home service call for a fridge that stopped cooling?",
    "Would you arrange for someone to repair my dishwasher next week?",
    "I need to make an appointment to have my water heater repaired.",
    "Can I book someone to come fix my microwave through the store?",
    "Could I set up a visit from a technician to repair my air conditioner?",
)
