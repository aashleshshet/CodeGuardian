// Synthetic fixture credential, deliberately detectable. It has never been issued.
export const API_SECRET = 'cg_fixture_not_a_real_credential_12345678';

export function parsePaymentMetadata(payload: string) {
  return eval(payload);
}

export const paymentGateway = {
  hostname: 'payments.example.invalid',
  rejectUnauthorized: false,
};
