"use strict";
/* globals $ */

/**
 * JSConfig is utility to manage preferences or config entries in the form of <name, value> pairs
 *
 * Simple usage:
 *   - Set up the JsConfig object:
 *     ``const
 *
 */
class JsConfig {

  // Assuming some browsers still do not have private and static fields

  // config field types
  static get _TYPE_BOOL() { return 0; }
  static get _TYPE_TEXT() { return 1; }
  static get _TYPE_NUM() { return 2; }
  static get _TYPE_ENUM() { return 3; }

  constructor(autoSave) {
    // The config data object. Use `new JsConfig()._` to access it
    this._ = {};
    // Private field holding the config entries's description
    this._desc = {};
    // listener
    this._onChangeListener = undefined;
    // automatically save UI changes
    this._autoSave = autoSave;
  }

  /**
   * Declares an additional config entry, setting initial/default values.
   * Triggers the change listener invocation.
   *
   * @param {string} name - Name of the config item
   * @param {object} typeDesc - Type of the config value, as returned by
   *                     boolType(), textType(), numType(), or EnumType()
   * @param {boolean|string|number} defaultValue - Default config value
   * @param {string} [readableDesc] - Description for this config entry, will be displayed as a tooltip
   * @param {string} [rowClass] - HTML class of the table row for this config
   * @returns this
   */
  add(name, typeDesc, defaultValue, readableDesc, rowClass) {
    this._desc[name] = {
      typeDesc: typeDesc,
      defaultValue: defaultValue,
      readableDesc: readableDesc,
      rowClass: rowClass
    };
    this._[name] = defaultValue;
    // notify changes
    this.change();
    return this;
  }

  /**
   * Creates a boolean type description
   *
   * @returns the created boolean type description
   */
  static boolType() {
    return {
      type: JsConfig._TYPE_BOOL
    };
  }

  /**
   * Creates a text type description
   *
   * @param {string} [pattern] - regexp pattern the value should match
   * @returns the created text type description
   */
  static textType(pattern) {
    return {
      type: JsConfig._TYPE_TEXT,
      pattern: pattern
    };
  }

  /**
   * Creates an enum type description
   *
   * @param  {...any} - enumeration of possible string values
   * @returns the created enum type description
   */
  static listType(...values) {
    return {
      type: JsConfig._TYPE_ENUM,
      values: values
    };
  }

  /**
   * Creates a numeric type description
   *
   * @param {number} [min] - min value
   * @param {number} [max] - max value
   * @param {number} [step] - increment for input form
   * @returns the created numeric type description
   */
  static numType(min, max, step) {
    return {
      type: JsConfig._TYPE_NUM,
      min: min,
      max: max,
      step: step
    };
  }

  /**
   * Sets the config with pre-defined values, overriding defaults.
   * Triggers the change listener invocation.
   *
   * @param {object.<string, boolean|string>} newConfig - An object with config entries, that will override existing config entries
   * @returns this
   */
  setConfig(newConfig) {
    if (typeof newConfig == "string" && newConfig) {
      try {
        newConfig = JSON.parse(newConfig);
      } catch (error) {
        console.warn("Cannot set configuration with invalid value: " + newConfig);
        newConfig = undefined;
      }
    }
    if (newConfig) {
      let _desc = this._desc;
      let _ = this._;
      $.each(newConfig, function (name, value) {
        if (typeof _desc[name] !== "undefined") {
          _[name] = value;
        }
      });
    }
    // notify changes
    this.change();
    return this;
  }

  /**
   * Resets the config to the default values.
   * Triggers the change listener invocation.
   *
   * @returns this
   */
  resetToDefault() {
    this._ = {};
    let _ = this._;
    $.each(this._desc, function (name, desc) {
      _[name] = desc.defaultValue;
    });
    // notify changes
    this.change();
    return this;
  }

  /**
   * Defines the function to call when config values are changed
   *
   * @param {function} fn - The change listener function (no arguments)
   * @returns this
   */
  onChange(fn) {
    this._onChangeListener = fn;
    return this;
  }

  /**
   * Invokes the change listener, if defined
   *
   * @returns this
   */
  change() {
    // notify changes
    if (this._onChangeListener) {
      this._onChangeListener(this._);
    }
    return this;
  }

  /**
   * Displays the configuration into a table, either editable or readonly
   *
   * @param {object} jqTable - a JQuery element for the target table to fill
   * @param {boolean} [readonly=false] - if set and true, the config not editable
   * @returns this
   */
  showConfigTable(jqTable, readonly) {
    jqTable.empty();
    let _ = this._;
    this._jqTable = jqTable;
    let jsc = this;
    $.each(this._desc, function (name, desc) {
      var tr = $(`<tr class="${desc.rowClass}">`);
      tr.append($('<td>').text(name + ":").attr('title', desc.readableDesc));
      let input;
      let val = _[name];
      let type = desc.typeDesc;
      switch (type.type) {

        case JsConfig._TYPE_BOOL:
          if (readonly) {
            input = val ? "TRUE" : "FALSE";
          } else  {
            input = $(`<input type="checkbox" id="${name}"/>`);
            input.prop('checked', val);
          }
          break;

        case JsConfig._TYPE_TEXT:
          if (readonly) {
            input = val;
          } else  {
            input = $(`<input type="text" id="${name}"/>`);
            input.val(val);
          }
          break;

        case JsConfig._TYPE_NUM:
          if (readonly) {
            input = val;
          } else  {
            input = $(`<input id="${name}" type="number">`);
            if (typeof type.min != undefined) {
              input.attr("min", type.min);
            }
            if (typeof type.max != undefined) {
              input.attr("max", type.max);
            }
            if (typeof type.step != undefined) {
              input.attr("step", type.step);
            }
            input.val(val);
          }
          break;

        case JsConfig._TYPE_ENUM:
          if (readonly) {
            input = val;
          } else  {
            input = $(`<select id="${name}">`);
            $.each(type.values, function (idx, optV) {
              input.append($(`<option value='${optV}'>`).text(optV));
            });
            input.val(val);
          }
          break;

        default:
          throw "Invalid type: " + type;
      }

      if (typeof input == 'object') {
        input.attr('title', desc.readableDesc);
      }
      tr.append($('<td>').append(input));
      jqTable.append(tr);
      if (jsc._autoSave) {
        input.on("change", () => { jsc.readConfigTable() });
      }
    });
    return this;
  }

  /**
   * Sets the config with the value from the table.
   * Triggers the change listener invocation.
   *
   * @param {JQuery element} jqTable - a JQuery element for the config table to read. If undefined, the table used in last showConfigTable() is reused.
   * @returns this
   */
  readConfigTable(jqTable) {
    if (!jqTable) {
      jqTable = this._jqTable;
    }
    let _ = this._;
    $.each(this._desc, function (name, desc) {
      let input = jqTable.find("#" + name);
      let type = desc.typeDesc;
      let v;

      try {

        switch (type.type) {

          case JsConfig._TYPE_BOOL:
            v = input.prop('checked');
            break;

          case JsConfig._TYPE_TEXT:
            v = input.val().trim();
            if (type.pattern) {
              if (!new RegExp(type.pattern).test(v)) {
                throw `Should match the pattern "${type.pattern}"`;
              }
            }
            break;

          case JsConfig._TYPE_NUM:
            v = parseFloat(input.val());
            if (
              (isNaN(v)) ||
              (typeof type.min !== "undefined" && v < type.min) ||
              (typeof type.max !== "undefined" && v > type.max)
            ) {
              throw `"${v}" not in valid range (${type.min} to ${type.max})`;
            }
            break;

          case JsConfig._TYPE_ENUM:
            v = input.val();
            if (type.values.indexOf(v) < 0) {
              throw `"${v}" is not a valid value`;
            }
            break;

          default:
            throw "Unknown type: " + type;
        }

        _[name] = v;

      } catch (error) {
        if (input?.length > 0) {
          input[0].focus();
        } else {
          input.focus();
        }
        throw `Cannot set "${name}" value: ${error}`;
      }

    });
    // notify changes
    this.change();
    return this;
  }

}
