namespace Netch.Forms;

public class SyncGlobalCheckBox : CheckBox
{
    public SyncGlobalCheckBox()
    {
        AutoCheck = false;
        OnSyncGlobalChanged();
    }

    private bool _syncGlobal;

    private bool _globalValue;

    [System.ComponentModel.Browsable(false)]
    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public bool SyncGlobal
    {
        get => _syncGlobal;
        set
        {
            if (value == _syncGlobal)
                return;

            _syncGlobal = value;

            OnSyncGlobalChanged();
        }
    }

    [System.ComponentModel.Browsable(false)]
    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public bool GlobalValue
    {
        get => _globalValue;
        set
        {
            if (value == _globalValue)
                return;

            _globalValue = value;

            if (SyncGlobal)
                Checked = value;
        }
    }

    protected override void OnClick(EventArgs e)
    {
        if (Checked == GlobalValue)
        {
            SyncGlobal = !SyncGlobal;
            if (SyncGlobal)
                return;
        }

        Checked = !Checked;
        base.OnClick(e);
    }

    [System.ComponentModel.Browsable(false)]
    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public bool? Value
    {
        get => _syncGlobal ? null : Checked;
        set
        {
            if (value == null)
            {
                SyncGlobal = true;
            }
            else
            {
                SyncGlobal = false;
                Checked = (bool)value;
            }
        }
    }

    private void OnSyncGlobalChanged()
    {
        if (_syncGlobal)
        {
            Font = new Font(Font, FontStyle.Regular);
            BackColor = SystemColors.Control;
        }
        else
        {
            Font = new Font(Font, FontStyle.Bold | FontStyle.Italic);
            BackColor = Color.Yellow;
        }
    }
}
