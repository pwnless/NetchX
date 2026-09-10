namespace NetchX.Forms
{
    partial class AboutForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.RepositoryLabel = new System.Windows.Forms.LinkLabel();
            this.NetchXPictureBox = new System.Windows.Forms.PictureBox();
            ((System.ComponentModel.ISupportInitialize)(this.NetchXPictureBox)).BeginInit();
            this.SuspendLayout();
            // 
            // RepositoryLabel
            // 
            this.RepositoryLabel.AutoSize = true;
            this.RepositoryLabel.Location = new System.Drawing.Point(111, 215);
            this.RepositoryLabel.Name = "RepositoryLabel";
            this.RepositoryLabel.Size = new System.Drawing.Size(123, 17);
            this.RepositoryLabel.TabIndex = 5;
            this.RepositoryLabel.TabStop = true;
            this.RepositoryLabel.Text = "GitHub Repository";
            this.RepositoryLabel.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.RepositoryLabel_LinkClicked);
            // 
            // NetchXPictureBox
            // 
            this.NetchXPictureBox.Cursor = System.Windows.Forms.Cursors.Hand;
            this.NetchXPictureBox.Image = global::NetchX.Properties.Resources.NetchX;
            this.NetchXPictureBox.Location = new System.Drawing.Point(72, 12);
            this.NetchXPictureBox.Name = "NetchXPictureBox";
            this.NetchXPictureBox.Size = new System.Drawing.Size(200, 200);
            this.NetchXPictureBox.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
            this.NetchXPictureBox.TabIndex = 0;
            this.NetchXPictureBox.TabStop = false;
            this.NetchXPictureBox.Click += new System.EventHandler(this.NetchXPictureBox_Click);
            // 
            // AboutForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(96F, 96F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;
            this.ClientSize = new System.Drawing.Size(338, 244);
            this.Controls.Add(this.RepositoryLabel);
            this.Controls.Add(this.NetchXPictureBox);
            this.Font = new System.Drawing.Font("微软雅黑", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.MaximizeBox = false;
            this.Name = "AboutForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "About";
            this.Load += new System.EventHandler(this.AboutForm_Load);
            ((System.ComponentModel.ISupportInitialize)(this.NetchXPictureBox)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.PictureBox NetchXPictureBox;
        private System.Windows.Forms.LinkLabel RepositoryLabel;
    }
}
