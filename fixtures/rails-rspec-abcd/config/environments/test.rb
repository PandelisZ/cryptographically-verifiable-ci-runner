Rails.application.configure do
  config.enable_reloading = false
  # Not `ENV["CI"].present?` (the generator's default): that makes every test
  # depend on the CI variable, so nothing attested on a laptop is skipped in CI.
  config.eager_load = false
  config.consider_all_requests_local = true
  config.cache_store = :null_store
  config.action_dispatch.show_exceptions = :rescuable
  config.action_controller.allow_forgery_protection = false
  config.active_support.deprecation = :stderr
end
