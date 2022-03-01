


- Generic optional arguments are quite inergonomic because the [None] variant requires a generic argument:
  F.e. `Option::<&bitcoin::EcdsaSighashType>::None`.
  This counts for all `Option<impl SomeTrait>` in arguments.

- Fix logging
