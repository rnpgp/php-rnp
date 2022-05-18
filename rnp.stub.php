<?php

/** @generate-class-entries */

function rnp_backend_string(): string {}

function rnp_backend_version(): string {}

function rnp_supported_features(string $type): string|false {}

function rnp_version_string(): string {}

function rnp_version_string_full(): string {}

final class rnp_ffi_t
{
}

function rnp_ffi_create(string $pub_format, string $sec_format): rnp_ffi_t|false {}

function rnp_ffi_destroy(rnp_ffi_t $ffi): void {}

function rnp_load_keys(rnp_ffi_t $ffi, string $format, string $input, int $flags): bool {}

function rnp_load_keys_from_path(rnp_ffi_t $ffi, string $format, string $input_path, int $flags): bool {}

function rnp_save_keys(rnp_ffi_t $ffi, string $format, string &$output, int $flags): bool {}

function rnp_save_keys_to_path(rnp_ffi_t $ffi, string $format, string $output_path, int $flags): bool {}

function rnp_dump_packets(string $input, int $flags): string|false {}

function rnp_dump_packets_to_json(string $input, int $flags): string|false {}
