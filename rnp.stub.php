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
