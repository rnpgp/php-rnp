<?php

/** @generate-class-entries */

function rnp_backend_string(): string {}

function rnp_backend_version(): string {}

function rnp_supported_features(string $type): string|false {}

function rnp_version_string(): string {}

function rnp_version_string_full(): string {}

final class RnpFFI
{
}

function rnp_ffi_create(string $pub_format, string $sec_format): RnpFFI|false {}

function rnp_ffi_destroy(RnpFFI $ffi): void {}

function rnp_load_keys(RnpFFI $ffi, string $format, string $input, int $flags): bool {}

function rnp_load_keys_from_path(RnpFFI $ffi, string $format, string $input_path, int $flags): bool {}

function rnp_save_keys(RnpFFI $ffi, string $format, string &$output, int $flags): bool {}

function rnp_save_keys_to_path(RnpFFI $ffi, string $format, string $output_path, int $flags): bool {}

function rnp_dump_packets(string $input, int $flags): string|false {}

function rnp_dump_packets_to_json(string $input, int $flags): string|false {}

function rnp_op_generate_key(RnpFFI $ffi, string $userid, string $key_alg, string $sub_alg = null, array $options = []): string|false {}

function rnp_ffi_set_pass_provider(RnpFFI $ffi, callable $password_callback): bool {}

function rnp_op_sign(RnpFFI $ffi, string $data, array $keys_fp, array $options = []): string|false {}

function rnp_op_sign_cleartext(RnpFFI $ffi, string $data, array $keys_fp, array $options = []): string|false {}

function rnp_op_sign_detached(RnpFFI $ffi, string $data, array  $keys_fp, array $options = []): string|false {}

function rnp_op_verify(RnpFFI $ffi, string $data): array|false {}

function rnp_op_verify_detached(RnpFFI $ffi, string $data, string $signature): array|false {}

function rnp_op_encrypt(RnpFFI $ffi, string $message, array $recipient_keys_fp, array $options = []): string|false {}

function rnp_decrypt(RnpFFI $ffi, string $input): string|false {}

function rnp_locate_key(RnpFFI $ffi, string $identifier_type, string $identifier): string|false {}

function rnp_list_keys(RnpFFI $ffi, string $identifier_type): array|false {}

function rnp_key_get_info(RnpFFI $ffi, string $key_fp): array|false {}

function rnp_key_export(RnpFFI $ffi, string $key_fp, int $flags): string|false {}

function rnp_key_export_autocrypt(RnpFFI $ffi, string $key_fp, string $subkey_fp, string $uid, int $flags): string|false {}

function rnp_import_keys(RnpFFI $ffi, string $input, int $flags): string|false {}

function rnp_key_remove(RnpFFI $ffi, string $key_fp, int $flags): bool {}

function rnp_key_revoke(RnpFFI $ffi, string $key_fp, int $flags, array $options = []): bool {}

function rnp_key_export_revocation(RnpFFI $ffi, string $key_fp, int $flags, array $options = []): string|false {}

function rnp_import_signatures(RnpFFI $ffi, string $input, int $flags): string|false {}
