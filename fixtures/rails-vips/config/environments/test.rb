Rails.application.configure do
  config.enable_reloading = false
  config.eager_load = false
  config.consider_all_requests_local = true
  config.cache_store = :null_store
  config.action_dispatch.show_exceptions = :rescuable
  config.action_controller.allow_forgery_protection = false
  config.active_support.deprecation = :stderr
  # Uploads go to tmp/storage (git-ignored): derived state a test may write.
  config.active_storage.service = :test
  config.active_job.queue_adapter = :test
end
