ActiveRecord::Schema[8.1].define(version: 2026_10_01_000000) do
  create_table "gadgets", force: :cascade do |t|
    t.string "name", null: false
  end

  create_table "widgets", force: :cascade do |t|
    t.string "name", null: false
    t.integer "size", default: 0, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end
end
