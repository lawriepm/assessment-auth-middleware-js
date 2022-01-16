module.exports = {
  "env": {
    "browser": false,
    "es2021": true
  },
  "parserOptions": {
    "ecmaVersion": "latest",
    "sourceType": "module"
  },
  "rules": {
    "no-unused-vars": ["error", { "vars": "all", "args": "after-used", "ignoreRestSiblings": false }],
    "quotes": [2, "double", { "avoidEscape": true }],
    "no-unused-expressions": ["error", { "allowTaggedTemplates": true }],
    "indent": ["error", 2]
  }
}
